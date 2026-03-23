#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <zlib.h>
#include <ctype.h>
#include <openssl/sha.h>

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
    char* object_id = argv[3];
    char* hash = object_id+2;
    char path[256];
    snprintf(path, sizeof(path), ".git/objects/%.*s/%s", 2, object_id, hash);

    FILE *fd = fopen(path, "rb");;
    uint8_t compressed[1024*4];
    size_t bytes_read = fread(compressed, sizeof(uint8_t), 1024 * 4, fd);
    fclose(fd);

    uLongf out_len = 1024 * 64;
    uint8_t output[out_len];
    int ret = uncompress(output, &out_len, (const Bytef*) compressed, (uLong) bytes_read);
    if (ret == Z_OK)
    {
      hexdump(output, out_len);
      const char* nullbyte = strchr((const char*) output, 0);
      printf("%s", (char*)nullbyte+1);
    }
  }
  else if (strcmp(command, "hash-object") == 0)
  {
    char* file_name = argv[3];
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

    uLongf compressed_len = compressBound(blob_size);
    uint8_t* compressed = (uint8_t*) malloc(compressed_len);
    int ret = compress2(compressed, &compressed_len, (const Bytef*) blob, (uLong) blob_size, Z_DEFAULT_COMPRESSION);
    if (ret == Z_OK)
    {
      unsigned char hash[SHA_DIGEST_LENGTH];
      SHA1(blob, blob_size, hash);

      char hash_str[SHA_DIGEST_LENGTH * 2 + 1];
      for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(hash_str + i * 2, "%02x", hash[i]);

      printf("%s\n", hash_str);

      char dir_path[256];
      snprintf(dir_path, sizeof(dir_path), ".git/objects/%.*s", 2, hash_str);
      mkdir(dir_path, 0755);
      char file_path[256];
      snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, hash_str + 2);


      FILE* fd = fopen(file_path, "wb");;
      size_t bytes_written = fwrite(compressed, sizeof(uint8_t), compressed_len, fd);
      fclose(fd);
    }
    free(blob);
    free(compressed);
  }
  else
  {
    fprintf(stderr, "Unknown command %s\n", command);
    return 1;
  }

  return 0;
}
