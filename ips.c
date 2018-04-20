/*
MIT License

Copyright (c) 2018 Julius Ikkala

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

struct stream
{
    uint8_t* data;
    size_t head, size;
};

bool read_binary_file(const char* path, struct stream* s)
{
    FILE* f = fopen(path, "rb");
    if(!f) return false;

    fseek(f, 0, SEEK_END);
    s->size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    s->data = malloc(s->size);
    if(fread(s->data, 1, s->size, f) != s->size)
    {
        free(s->data);
        s->data = NULL;
        fclose(f);
        return false;
    }
    s->head = 0;

    fclose(f);
    return true;
}

bool write_binary_file(const char* path, const struct stream* s)
{
    FILE* f = fopen(path, "wb");
    if(!f) return false;

    if(fwrite(s->data, 1, s->size, f) != s->size) return false;

    fclose(f);
    return true;
}

void free_stream(struct stream* s)
{
    if(s && s->data) free(s->data);
    s->data = NULL;
    s->head = 0;
    s->size = 0;
}

void expand_stream(struct stream *s, size_t new_size)
{
    if(s->size >= new_size) return;
    s->data = realloc(s->data, new_size);
    memset(s->data + s->size, 0, new_size - s->size);
    s->size = new_size;
}

bool patch_hunk(
    struct stream* patch,
    struct stream* data,
    bool* finished
){
    uint32_t offset = 0;
    uint32_t length = 0;

    if(patch->size < patch->head + 5)
    {
        *finished = true;
        return true;
    }

    // Read offset (values are in big endian)
    offset =
        ((uint32_t)patch->data[patch->head + 0] << 16) |
        ((uint32_t)patch->data[patch->head + 1] << 8) |
        ((uint32_t)patch->data[patch->head + 2]);

    patch->head += 3;

    if(offset == 0x454f46)
    {
        *finished = true;
        return true;
    }

    length = ((uint32_t)patch->data[patch->head + 0] << 8) |
             ((uint32_t)patch->data[patch->head + 1]);

    patch->head += 2;

    if(length == 0)
    {// RLE
        if(patch->size < patch->head + 3) return false;

        uint8_t value = 0;
        length = ((uint32_t)patch->data[patch->head + 0] << 8) |
                 ((uint32_t)patch->data[patch->head + 1]);
        patch->head += 2;

        value = patch->data[patch->head];
        patch->head += 1;

        expand_stream(data, offset + length);

        while(length--) data->data[offset++] = value;
    }
    else
    {
        if(patch->size < patch->head + length)
            return false;

        expand_stream(data, offset + length);
        while(length--) data->data[offset++] = patch->data[patch->head++];
    }

    return true;
}

int main(int argc, char** argv)
{
    struct stream patch = {0};
    struct stream data = {0};

    if(argc != 4)
    {
        printf("Usage: %s patchfile infile outfile\n", argv[0]);
        goto fail;
    }

    if(!read_binary_file(argv[1], &patch))
    {
        printf("Failed to open %s\n", argv[1]);
        goto fail;
    }

    if(strncmp("PATCH", (char*)patch.data, 5) != 0)
    {
        printf("%s is not an IPS patch file!\n", argv[1]);
        goto fail;
    }
    patch.head += 5;

    if(!read_binary_file(argv[2], &data))
    {
        printf("Failed to open %s\n", argv[2]);
        goto fail;
    }

    bool finished = false;
    while(!finished)
    {
        if(!patch_hunk(&patch, &data, &finished))
        {
            printf("Failed to patch, invalid hunk.\n");
            goto fail;
        }
    }

    if(!write_binary_file(argv[3], &data))
    {
        printf("Failed to write %s\n", argv[3]);
        goto fail;
    }

    free_stream(&patch);
    free_stream(&data);
    return 0;

fail:
    free_stream(&patch);
    free_stream(&data);
    return 1;
}
