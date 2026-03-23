#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <zlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <dirent.h>

void hexdump(const void* data, size_t size)
{
  const unsigned char* byte = (const unsigned char*) data;
  char buffer[4096];
  size_t buf_used = 0;
  size_t i, j;

  for (i = 0; i < size; i += 16)
  {
    char line[80];  // A line won't exceed 80 chars
    int len = snprintf(line, sizeof(line), "%08zx  ", i);

    // Hex part
    for (j = 0; j < 16; j++)
    {
      if (i + j < size)
        len += snprintf(line + len, sizeof(line) - len, "%02x ", byte[i + j]);
      else
        len += snprintf(line + len, sizeof(line) - len, "   ");
      if (j == 7)
        len += snprintf(line + len, sizeof(line) - len, " ");
    }

    // ASCII part
    len += snprintf(line + len, sizeof(line) - len, " |");
    for (j = 0; j < 16 && i + j < size; j++)
    {
      unsigned char ch = byte[i + j];
      len += snprintf(line + len, sizeof(line) - len, "%c", isprint(ch) ? ch : '.');
    }
    len += snprintf(line + len, sizeof(line) - len, "|\n");

    // Append line to buffer
    if (buf_used + len < sizeof(buffer))
    {
      memcpy(buffer + buf_used, line, len);
      buf_used += len;
    } else
    {
      // Prevent buffer overflow
      break;
    }
  }

  // Null-terminate and print once
  buffer[buf_used] = '\0';
  fprintf(stderr, "Idx       | Hex                                             | ASCII\n"
                  "----------+-------------------------------------------------+-----------------\n"
    "%s",
    buffer);
}


int get_uncompressed(const char* object_id, uint8_t *output, size_t *out_len)
{
  const char* filename = object_id + 2;
  char path[256];
  snprintf(path, sizeof(path), ".git/objects/%.*s/%s", 2, object_id, filename);

  FILE* fd = fopen(path, "rb");;
  uint8_t compressed[1024 * 4];
  size_t bytes_read = fread(compressed, sizeof(uint8_t), 1024 * 4, fd);
  fclose(fd);

  int ret = uncompress(output, out_len, (const Bytef*) compressed, (uLong) bytes_read);
  if (ret == Z_OK)
  {
    return 1;
  }
  return 0;
}

void hash_to_str(uint8_t* hash, char* out)
{
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(out + i * 2, "%02x", hash[i]);
}
void print_hash(uint8_t* hash)
{
  if (hash == 0) return;
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    printf("%02x", hash[i]);
  printf("\n");
}

uint8_t* write_object(uint8_t* raw, size_t raw_len)
{
  uLongf compressed_len = compressBound(raw_len);
  uint8_t* compressed = (uint8_t*) malloc(compressed_len);

  if (compress2(compressed, &compressed_len, (const Bytef*) raw, (uLong) raw_len, Z_DEFAULT_COMPRESSION) != Z_OK)
  {
    free(compressed);
    return 0;
  }

  uint8_t* id = (uint8_t*) malloc(SHA_DIGEST_LENGTH);
  SHA1(raw, raw_len, id);

  char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
  hash_to_str(id, hash_str);

  char dir_path[256];
  snprintf(dir_path, sizeof(dir_path), ".git/objects/%.*s", 2, hash_str);
  mkdir(dir_path, 0755);
  char file_path[256];
  snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, hash_str + 2);

  FILE* fd = fopen(file_path, "wb");
  size_t bytes_written = fwrite(compressed, sizeof(uint8_t), compressed_len, fd);
  fclose(fd);

  free(compressed);
  return id;
}

uint8_t* create_object(char *file_name)
{
  uint8_t* hash = 0;
  FILE* fd = fopen(file_name, "rb");
  fseek(fd, 0, SEEK_END);
  size_t file_size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  char header[64];
  size_t header_len = snprintf(header, sizeof(header), "blob %zu", file_size);
  size_t blob_size = file_size + header_len + 1;
  uint8_t* blob = (uint8_t*) malloc(blob_size);
  memcpy(blob, header, header_len + 1);
  size_t bytes_read = fread(blob + header_len + 1, sizeof(uint8_t), file_size, fd);
  fclose(fd);

  hash = write_object(blob, blob_size);
  free(blob);
  return hash;
}

uint8_t* create_tree(char *root_path)
{
  uint8_t* data = (uint8_t*) malloc(1024 * 200);
  uint8_t* cursor = data;
  struct dirent** entries;
  int n = scandir(root_path, &entries, NULL, alphasort);
  for (int i = 0; i < n; ++i)
  {
    struct dirent* entry = entries[i];
    if (entry->d_name[0] == '.')
    {
      free(entries[i]);
      continue;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/%s", root_path, entry->d_name);
    uint8_t* hash = 0;
    if (entry->d_type == DT_DIR)
    {
      cursor += snprintf(cursor, 256, "40000 %s", entry->d_name) + 1;
      hash = create_tree(path);
    } else if (entry->d_type == DT_REG)
    {
      cursor += snprintf(cursor, 256, "100644 %s", entry->d_name) + 1;
      hash = create_object(path);
    }
    if (hash)
    {
      memcpy(cursor, hash, SHA_DIGEST_LENGTH);
      cursor += SHA_DIGEST_LENGTH;
      free(hash);
    }
    free(entries[i]);
  }

  size_t data_len = cursor - data;
  char tree_header[64];
  size_t tree_header_len = snprintf(tree_header, 64, "tree %zu", data_len);
  size_t tree_data_len = data_len + tree_header_len + 1;

  uint8_t* tree_data = (uint8_t*) malloc(tree_data_len);
  memcpy(tree_data, tree_header, tree_header_len + 1);
  memcpy(tree_data + tree_header_len + 1, data, data_len);

  uint8_t* tree_id = write_object(tree_data, tree_data_len);

  free(entries);
  free(data);
  free(tree_data);
  return tree_id;
}


int main(int argc, char* argv[])
{
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (argc < 2)
  {
    fprintf(stderr, "Usage: ./your_program.sh <command> [<args>]\n");
    return 1;
  }

  const char* command = argv[1];

  if (strcmp(command, "init") == 0)
  {
    fprintf(stderr, "Logs from your program will appear here!\n");


    if (mkdir(".git", 0755) == -1 ||
      mkdir(".git/objects", 0755) == -1 ||
      mkdir(".git/refs", 0755) == -1)
    {
      fprintf(stderr, "Failed to create directories: %s\n", strerror(errno));
      return 1;
    }

    FILE* headFile = fopen(".git/HEAD", "w");
    if (headFile == NULL)
    {
      fprintf(stderr, "Failed to create .git/HEAD file: %s\n", strerror(errno));
      return 1;
    }
    fprintf(headFile, "ref: refs/heads/main\n");
    fclose(headFile);

    printf("Initialized git directory\n");
  } 
  else if (strcmp(command, "cat-file") == 0)
  {
    size_t data_len = 1024 * 64;
    uint8_t* data = (uint8_t*)malloc(data_len);
    if (get_uncompressed(argv[3], data, &data_len))
    {
      hexdump(data, data_len);
      const char* nullbyte = strchr((const char*) data, 0);
      printf("%s", (char*)nullbyte+1);
    }
    free(data);
  }
  else if (strcmp(command, "hash-object") == 0)
  {
    print_hash(create_object(argv[3]));
  }
  else if (strcmp(command, "ls-tree") == 0)
  {
    size_t data_len = 1024 * 64;
    uint8_t* data = (uint8_t*) malloc(data_len);
    if (!get_uncompressed(argv[3], data, &data_len))
    {
      free(data);
      return 0;
    }

    const char* cursor = strchr((const char*) data, 0) + 1;
    char* end = (char*) data + data_len;
    while (cursor < end)
    {
      char* name = strchr((const char*) cursor, ' ') + 1;
      cursor = strchr((const char*) name, 0) + 21;
      printf("%s\n", name);
    }
    free(data);
  }
  else if (strcmp(command, "write-tree") == 0)
  {
    print_hash(create_tree("."));
  }
  else
  {
    fprintf(stderr, "Unknown command %s\n", command);
    return 1;
  }

  return 0;
}
