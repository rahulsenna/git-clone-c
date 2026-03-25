#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <zlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <dirent.h>
#include <time.h>

#define SHA1_STR_LEN (SHA_DIGEST_LENGTH * 2 + 1)

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


typedef struct
{
  uint8_t* data;
  size_t   len;
} BYTES;


BYTES get_uncompressed(const char* object_id)
{
  const char* filename = object_id + 2;
  char path[256];
  snprintf(path, sizeof(path), ".git/objects/%.*s/%s", 2, object_id, filename);

  FILE* fd = fopen(path, "rb");
  if (!fd)
  {
    fprintf(stderr, "get_uncompressed: cannot open %s\n", path);
    return (BYTES){0};
  }
  fseek(fd, 0, SEEK_END);
  size_t file_size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  uint8_t* compressed = (uint8_t*) malloc(file_size);
  size_t bytes_read = fread(compressed, sizeof(uint8_t), file_size, fd);
  fclose(fd);

  BYTES res = { 0 };
  res.len = file_size * 10;
  res.data = (uint8_t*) malloc(res.len);

  int ret = uncompress(res.data, &res.len, (const Bytef*) compressed, (uLong) bytes_read);
  free(compressed);
  if (ret == Z_OK)
  {
    return res;
  }

  free(res.data);
  res.data = 0;
  return res;
}

void hash_to_str(uint8_t* hash, char* out)
{
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(out + i * 2, "%02x", hash[i]);
}
char* hash_to_str_mem(uint8_t* hash)
{
  if (hash == NULL)
    return 0;
  char* res = (char*) malloc(SHA1_STR_LEN);
  hash_to_str(hash, res);
  free(hash);
  return res;
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

  char hash_str[SHA1_STR_LEN];
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

uint8_t* create_object(char* file_name)
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

uint8_t* create_tree(char* root_path)
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

void git_init()
{
  if (mkdir(".git", 0755) == -1 ||
    mkdir(".git/objects", 0755) == -1 ||
    mkdir(".git/refs", 0755) == -1)
  {
    fprintf(stderr, "Failed to create directories: %s\n", strerror(errno));
    return;
  }

  FILE* headFile = fopen(".git/HEAD", "w");
  if (headFile == NULL)
  {
    fprintf(stderr, "Failed to create .git/HEAD file: %s\n", strerror(errno));
    return;
  }
  fprintf(headFile, "ref: refs/heads/main\n");
  fclose(headFile);
}

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>


static size_t write_cb(void* src, size_t size, size_t nmemb, void* userp)
{
  size_t new_bytes = size * nmemb;
  BYTES* buf = (BYTES*) userp;
  buf->data = realloc(buf->data, buf->len + new_bytes + 1);
  memcpy(buf->data + buf->len, src, new_bytes);
  buf->len += new_bytes;
  buf->data[buf->len] = 0;
  return new_bytes;
}

BYTES http_request(const char* url,
  const char** headers,
  const uint8_t* body, size_t body_len)
{
  BYTES resp = { 0 };

  CURL* curl = curl_easy_init();
  if (!curl) return resp;

  struct curl_slist* hlist = NULL;
  if (headers)
    for (int i = 0; headers[i]; i++)
      hlist = curl_slist_append(hlist, headers[i]);

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

  if (body)
  {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) body_len);
  }

  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    fprintf(stderr, "curl: %s\n", curl_easy_strerror(res));

  curl_slist_free_all(hlist);
  curl_easy_cleanup(curl);
  return resp;
}

BYTES fetch_pack_file_git_protocol_1(char* git_url)
{
  curl_global_init(CURL_GLOBAL_ALL);
  char full_url[256];
  snprintf(full_url, sizeof(full_url), "%s/info/refs?service=git-upload-pack", git_url);

  BYTES res = http_request(full_url, 0, 0, 0);
  char* head_sha1 = res.data + 38;
  mkdir(".git/refs/heads", 0755);

  FILE* fd = fopen(".git/refs/heads/master", "wb");
  size_t bytes_written = fwrite(head_sha1, sizeof(uint8_t), 40, fd);
  fclose(fd);

  char body[128];
  size_t body_len = snprintf(body, sizeof(body), "0032want %.*s\n00000009done\n", 40, head_sha1);

  snprintf(full_url, sizeof(full_url), "%s/git-upload-pack", git_url);
  BYTES res2 = http_request(full_url, 0, body, body_len);

  free(res.data);
  curl_global_cleanup();
  return res2;
}

typedef enum
{
  Commit = 1,
  Tree = 2,
  Blob = 3,
  Tag = 4,
  // Type 5 is reserved/unused
  OfsDelta = 6,
  RefDelta = 7
} GitObjectType;


int parse_variable_length(uint8_t* data, size_t offset, GitObjectType* type, size_t* size)
{
  uint8_t* first_byte = data + offset;
  *type = (GitObjectType) ((*first_byte >> 4) & 0x07);
  *size = *first_byte & 0x0F;

  int current_offset = offset + 1;
  int shift = 4;

  while ((data[current_offset - 1] & 0x80) != 0) // MSB set
  {
    uint8_t next_byte = data[current_offset];
    *size |= (size_t) (next_byte & 0x7F) << shift;
    shift += 7;
    current_offset++;
  }

  return current_offset - offset; // bytes consumed
}

BYTES inflate_object(uint8_t* cursor, size_t expected_size, size_t* consumed)
{
  z_stream strm = { 0 };
  if (inflateInit(&strm) != Z_OK)
    return (BYTES) { 0 };

  uint8_t* out = (uint8_t*) malloc(expected_size);
  strm.next_in = cursor;
  strm.avail_in = INT_MAX;
  strm.next_out = out;
  strm.avail_out = expected_size;

  int ret = inflate(&strm, Z_FINISH);
  inflateEnd(&strm);

  if (ret != Z_STREAM_END)
  {
    free(out);
    return (BYTES) { 0 };
  }
  
  BYTES res = { 0 };
  res.data = out;
  res.len = expected_size;
  *consumed = strm.total_in;
  return res;
}

void process_one_object(char* header, size_t header_len, BYTES object)
{
  size_t git_obj_len = object.len + header_len + 1;
  uint8_t* git_obj = (uint8_t*) malloc(object.len + header_len + 1);
  memcpy(git_obj, header, header_len + 1);
  memcpy(git_obj + header_len + 1, object.data, object.len);

  write_object(git_obj, git_obj_len);
  free(git_obj);
}

void process_objects(GitObjectType type, BYTES object)
{
  char header[64];
  switch (type)
  {
    case Commit:
    {
      size_t header_len = snprintf(header, sizeof(header), "commit %zu", object.len);
      process_one_object(header, header_len, object);
      break;
    }
    case Blob:
    {
      size_t header_len = snprintf(header, sizeof(header), "blob %zu", object.len);
      process_one_object(header, header_len, object);
      break;
    }
    case Tree:
    {
      size_t header_len = snprintf(header, sizeof(header), "tree %zu", object.len);
      process_one_object(header, header_len, object);
      break;
    }
    default: break;
  }
}


size_t read_variable_length(uint8_t* data, size_t* position)
{
  uint8_t b = data[(*position)++];
  size_t size = b & 0x7F;
  int shift = 7;

  while ((b & 0x80) != 0)
  {
    b = data[(*position)++];
    size |= (long) (b & 0x7F) << shift;
    shift += 7;
  }
  return size;
}

#define err_and_exit(obj, fmt, ...) ({       \
  fprintf(stderr, fmt "\n", ##__VA_ARGS__);    \
  free((obj).data);                            \
  (BYTES){0};                                  \
})

BYTES apply_delta(BYTES base_object, size_t base_offset, BYTES delta_data)
{
  size_t delta_pos = 0;
  size_t source_length = read_variable_length(delta_data.data, &delta_pos);
  BYTES res = { 0 };
  if (source_length != base_object.len - base_offset)
  {
    return err_and_exit(res, "Delta source length mismatch: expected %zu, got %zu\n", base_object.len - base_offset, source_length);
  }

  size_t target_length = read_variable_length(delta_data.data, &delta_pos);

  res.data = (uint8_t*) malloc(target_length);
  res.len = target_length;
  size_t res_pos = 0;
  BYTES base_data = { base_object.data + base_offset, base_object.len - base_offset };

  while (delta_pos < delta_data.len)
  {
    uint8_t instruction = delta_data.data[delta_pos++];

    if ((instruction & 0x80) != 0) // Copy instruction (MSB = 1)
    {
      int offset = 0;
      int size = 0;

      if ((instruction & 0x01) != 0) offset |= delta_data.data[delta_pos++];
      if ((instruction & 0x02) != 0) offset |= delta_data.data[delta_pos++] << 8;
      if ((instruction & 0x04) != 0) offset |= delta_data.data[delta_pos++] << 16;
      if ((instruction & 0x08) != 0) offset |= delta_data.data[delta_pos++] << 24;

      if ((instruction & 0x10) != 0) size |= delta_data.data[delta_pos++];
      if ((instruction & 0x20) != 0) size |= delta_data.data[delta_pos++] << 8;
      if ((instruction & 0x40) != 0) size |= delta_data.data[delta_pos++] << 16;

      if (size == 0) size = 0x10000;

      if (offset + size > base_data.len)
      {
        return err_and_exit(res, "Delta copy exceeds base object bounds");
      }

      memcpy(res.data + res_pos, base_data.data + offset, size);
      res_pos += size;
    } else // Insert instruction (MSB = 0)
    {

      int insert_size = instruction; // Lower 7 bits = size
      if (insert_size == 0)
      {
        return err_and_exit(res, "Invalid insert instruction with size 0");
      }

      if (delta_pos + insert_size > delta_data.len)
      {
        return err_and_exit(res, "Delta insert exceeds delta data bounds");
      }

      memcpy(res.data + res_pos, delta_data.data + delta_pos, insert_size);

      delta_pos += insert_size;
      res_pos += insert_size;
    }
  }

  if (res_pos != target_length)
  {
    return err_and_exit(res, "Delta result size mismatch: expected target_len %zu, got result.len %zu", target_length, res_pos);
  }
  return res;
}

void unpack_packfile(uint8_t* pack_data)
{
  uint32_t object_count = (pack_data[8] << 24) | (pack_data[9] << 16) | (pack_data[10] << 8) | pack_data[11];
  int current_offset = 12;
  for (uint i = 0; i < object_count; ++i)
  {
    GitObjectType type;
    size_t varlen_size;
    int varlen = parse_variable_length(pack_data, current_offset, &type, &varlen_size);
    current_offset += varlen;
    size_t consumed = 0;
    switch (type)
    {
      case Commit:
      case Blob:
      case Tree:
      case Tag:
      {
        BYTES object = inflate_object(pack_data + current_offset, varlen_size, &consumed);
        current_offset += consumed;
        process_objects(type, object);
        free(object.data);
        break;
      }
      case RefDelta:
      {
        char baseObjectHex[SHA1_STR_LEN];
        hash_to_str(pack_data + current_offset, baseObjectHex);
        current_offset += 20;

        BYTES delta = inflate_object(pack_data + current_offset, varlen_size, &consumed);
        current_offset += consumed;

        BYTES base_obj = get_uncompressed(baseObjectHex);
        if (!base_obj.data)
          break;

        char* nullbyte = strchr((const char*) base_obj.data, 0);
        base_obj.len -= (size_t) ((uint8_t*) nullbyte - base_obj.data) + 1;


        char* type_str = base_obj.data;
        GitObjectType base_object_type = 0;
        if (strncmp(type_str, "commit", strlen("commit")) == 0)
          base_object_type = Commit;
        else if (strncmp(type_str, "blob", strlen("blob")) == 0)
          base_object_type = Blob;
        else if (strncmp(type_str, "tree", strlen("tree")) == 0)
          base_object_type = Tree;
        else if (strncmp(type_str, "tag", strlen("tag")) == 0)
          base_object_type = Tag;

        BYTES base_object = { nullbyte + 1, base_obj.len };
        BYTES reconstructedObject = apply_delta(base_object, 0, delta);
        process_objects(base_object_type, reconstructedObject);
        free(delta.data);
        free(base_obj.data);
        free(reconstructedObject.data);
        break;
      }
      case OfsDelta:
      {
        fprintf(stderr, "OfsDelta NOT SUPPORTED\n");
        break;
      }
      default: {
        fprintf(stderr, "NOT SUPPORTED type: %02x\n", type);
        break;
      };
    }
  }
}

void load_tree(char* tree_id, char* path)
{

  BYTES tree = get_uncompressed(tree_id);
  if (tree.data == NULL) return;

  char* cursor = strchr((const char*) tree.data, 0) + 1;
  char* end = (char*) tree.data + tree.len;
  while (cursor < end)
  {
    char* mode = cursor;
    char* name = strchr((const char*) cursor, ' ') + 1;
    cursor = strchr((const char*) name, 0) + 1;
    char object_id[SHA1_STR_LEN];
    hash_to_str(cursor, object_id);
    cursor += 20;

    char fullpath[256];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, name);

    if (strncmp(mode, "40000", strlen("40000")) == 0)
    {
      mkdir(path, 0755);
      load_tree(object_id, fullpath);
    } else if (strncmp(mode, "100644", strlen("100644")) == 0)
    {
      mkdir(path, 0755);
      FILE* fd = fopen(fullpath, "wb");
      if (!fd)
      {
        fprintf(stderr, "load_tree: cannot open %s\n", fullpath);
        return;
      }
      BYTES file = get_uncompressed(object_id);
      uint8_t* content_ptr = strchr(file.data, 0) + 1;
      file.len -= (size_t) (content_ptr - file.data);
      size_t bytes_written = fwrite(content_ptr, sizeof(uint8_t), file.len, fd);
      fclose(fd);
      free(file.data);
    }
  }
  free(tree.data);
}

void load_git_objects()
{
  FILE* fd = fopen(".git/refs/heads/master", "rb");
  char head_commit_id[SHA1_STR_LEN];
  fread(head_commit_id, sizeof(uint8_t), SHA1_STR_LEN, fd);
  head_commit_id[40] = 0;
  fclose(fd);

  BYTES commit = get_uncompressed(head_commit_id);
  char* commit_start = strchr(commit.data, 0) + 1;

  char* tree_id_ptr = strstr(commit_start, "tree ") + 5;
  char tree_id[SHA1_STR_LEN];
  snprintf(tree_id, sizeof(tree_id), "%s", tree_id_ptr);

  load_tree(tree_id, ".");
  free(commit.data);
}

void git_clone(char* url, char* save_dir)
{
  if (save_dir)
  {
    rmdir(save_dir);
    mkdir(save_dir, 0755);
    chdir(save_dir);
  }

  git_init();
  BYTES pack = fetch_pack_file_git_protocol_1(url);
  unpack_packfile(pack.data + 8);
  free(pack.data);
  load_git_objects();
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
    git_init();
    printf("Initialized git directory\n");
  } 
  else if (strcmp(command, "cat-file") == 0)
  {
    BYTES git_obj = get_uncompressed(argv[3]);
    if (git_obj.data != NULL)
    {
      const char* nullbyte = strchr((const char*) git_obj.data, 0);
      printf("%s", (char*)nullbyte+1);
    }
    free(git_obj.data);
  }
  else if (strcmp(command, "hash-object") == 0)
  {
    print_hash(create_object(argv[3]));
  }
  else if (strcmp(command, "ls-tree") == 0)
  {
    BYTES git_obj = get_uncompressed(argv[3]);
    if (git_obj.data == NULL)
      return 0;
    
    const char* cursor = strchr((const char*) git_obj.data, 0) + 1;
    char* end = (char*) git_obj.data + git_obj.len;
    while (cursor < end)
    {
      char* name = strchr((const char*) cursor, ' ') + 1;
      cursor = strchr((const char*) name, 0) + 21;
      printf("%s\n", name);
    }
    free(git_obj.data);
  }
  else if (strcmp(command, "write-tree") == 0)
  {
    print_hash(create_tree("."));
  }
  else if (strcmp(command, "commit-tree") == 0)
  {
    char* tree = argv[2];
    char* parent = argv[4];
    char* message = argv[6];

    char tz[6];
    time_t ts = time(0);
    struct tm* local = localtime(&ts);
    snprintf(tz, sizeof(tz), "%+03ld%02ld", local->tm_gmtoff / 3600, labs(local->tm_gmtoff % 3600) / 60);

    char commit_buf[1024];

    size_t commit_buf_len = snprintf(commit_buf, sizeof(commit_buf),
      "tree %s\n"
      "parent %s\n"
      "author Tom Baray <tom@patriots.com> %ld %s\n"
      "committer Tom Baray <tom@patriots.com> %ld %s\n"
      "\n"
      "%s\n", tree, parent, ts, tz, ts, tz, message);

    char commit_blob[1024];
    size_t header_len = snprintf(commit_blob, sizeof(commit_blob), "commit %zu", commit_buf_len);
    memcpy(commit_blob + header_len + 1, commit_buf, commit_buf_len);

    print_hash(write_object(commit_blob, commit_buf_len + header_len + 1));
  }
  else if (strcmp(command, "clone") == 0)
  {
    char* url = argv[2];
    char* save_dir = argv[3];
    
    git_clone(url, save_dir);
  }
  else
  {
    fprintf(stderr, "Unknown command %s\n", command);
    return 1;
  }

  return 0;
}
