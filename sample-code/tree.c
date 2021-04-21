#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef int index_t;
typedef int index_diff_t;

struct Node
{
    int value;
    index_t index;
};

struct Key
{
    int flags;
    int number;
    size_t len;
    char key[1];
};

struct ProofSet
{
    struct Node *InputSet;
    struct Node *OutputSet;
    size_t InputSize, OutputSize;
};

int SingleHash(struct Key *key)
{
    return key->number;
}

int DoubleHash(struct Node *left, struct Node *right)
{
    return left->value + right->value;
}

void PrintProofSet(const struct ProofSet *ps)
{
    for (size_t i = 0; i < ps->InputSize; i++)
    {
        printf("(%d, %d)", ps->InputSet[i].index, ps->InputSet[i].value);
    }
    printf("\n");
    for (size_t o = 0; o < ps->OutputSize; o++)
    {
        printf("(%d, %d)", ps->OutputSet[o].index, ps->OutputSet[o].value);
    }
    printf("\n");
}

void LoadInputSet(struct ProofSet *ps)
{
    for (size_t i = 0; i < ps->InputSize; i++)
    {
        ps->InputSet[i].value = ps->InputSet[i].index;
    }
}

void SaveOutputSet(const struct ProofSet *ps)
{
    for (size_t o = 1; o < ps->OutputSize; o++)
    {

    }
}

index_t GetSubrootIndex(index_t min, index_t max)
{
    index_diff_t LeftNodes = max - min + 1, h = 1;
    while (LeftNodes - h >= 0)
    {
        LeftNodes -= h;
        h <<= 1;
    }
    if (LeftNodes == 0)
        return (max - min) / 2 + min;
    else
        return max - LeftNodes + 1;
}

size_t GetHeight(index_t RootIndex)
{
    size_t height = 0;
    while (RootIndex != 0)
    {
        height++;
        RootIndex >>= 1;
    }
    return height;
}

struct ProofSet *GenAuthPath(int c, index_t RootIndex, index_t LeafIndex)
{
    struct ProofSet *ps = (struct ProofSet *)malloc(sizeof(struct ProofSet));
    index_t min = 1, max = 2 * c - 1;
    size_t i = 0, o = 0;
    ps->OutputSize = GetHeight(RootIndex);
    ps->InputSize = ps->OutputSize - 1;
    // malloc 0的问题
    ps->InputSet = (struct Node *)malloc(ps->InputSize * sizeof(struct Node));
    ps->OutputSet = (struct Node *)malloc(ps->OutputSize * sizeof(struct Node));
    while (RootIndex != LeafIndex)
    {
        ps->OutputSet[o++].index = RootIndex;
        if (RootIndex < LeafIndex)
        {
            ps->InputSet[i++].index = GetSubrootIndex(min, RootIndex - 1);
            min = RootIndex + 1;
        }
        else
        {
            ps->InputSet[i++].index = GetSubrootIndex(RootIndex + 1, max);
            max = RootIndex - 1;
        }
        RootIndex = GetSubrootIndex(min, max);
    }
    ps->OutputSet[o++].index = LeafIndex;
    ps->InputSize = i;
    ps->OutputSize = o;
    // PrintProofSet(ps);
    return ps;
}

void UpdAuthPath(struct ProofSet *ps)
{
    struct Node *upd;
    index_t i, o;
    upd = &ps->OutputSet[ps->OutputSize - 1];
    for (i = ps->InputSize, o = ps->OutputSize - 1; i > 0 && o > 0; i--, o--)
    {
        if (ps->InputSet[i - 1].index < upd->index)
        {
            ps->OutputSet[o - 1].value = DoubleHash(&ps->InputSet[i - 1], upd);
        }
        else
        {
            ps->OutputSet[o - 1].value = DoubleHash(upd, &ps->InputSet[i - 1]);
        }
        upd = &ps->OutputSet[o - 1];
    }
    PrintProofSet(ps);
}

void Init(int *c)
{
    *c = 0;
}

void Append(int *c, struct Node *root, struct Key *key)
{
    if (*c == 0)
    {
        root->value = SingleHash(key);
        root->index = 1;
        ++*c;
    }
    else
    {
        struct ProofSet *ps;
        struct Node *leaf;
        if (root->index - 1 == 2 * (*c) - 1 - root->index)
        {
            root->index = 2 * (*c);
        }
        ++*c;
        ps = GenAuthPath(*c, root->index, 2 * (*c) - 1);
        LoadInputSet(ps);
        ps->OutputSet[ps->OutputSize - 1].value = SingleHash(key);
        UpdAuthPath(ps);
        root->value = ps->OutputSet[0].value;
        SaveOutputSet(ps);
    }
}

void Revoke(int c, struct Node *root, struct Key *key)
{
    struct ProofSet *ps;
    if (c == 0)
        return;
    if (key->flags)
        return;
    ps = GenAuthPath(c, root->index, 2 * key->number + 1);
    LoadInputSet(ps);
    key->flags = 1;
    ps->OutputSet[ps->OutputSize - 1].value = SingleHash(key);
    UpdAuthPath(ps);
    root->value = ps->OutputSet[0].value;
    SaveOutputSet(ps);
}

bool Verify(int c, struct Node *root, struct Key *key)
{
    struct ProofSet *ps;
    if (c == 0)
        return false;
    if (key->flags)
        return false;
    ps = GenAuthPath(c, root->index, 2 * key->number + 1);
    LoadInputSet(ps);
    ps->OutputSet[ps->OutputSize - 1].value = SingleHash(key);
    UpdAuthPath(ps);
    if (root->value = ps->OutputSet[0].value)
        return true;
    else
        return false;
}

int main()
{
    int c;
    struct Node root = {0, 0};
    int i = 0;
    struct Key key = {0, 0, 0, '\0'};
    Init(&c);
    for (i = 0; i < 16; i++)
    {
        printf("Append key %d(node %d)\n", i, 2 * i + 1);
        key.number = 2 * i + 1;
        Append(&c, &root, &key);
    }
    for (i = 0; i < 16; i += 2)
    {
        printf("Revoke key %d(node %d)\n", i, 2 * i + 1);
        key.flags = 0;
        key.number = i;
        Revoke(c, &root, &key);
    }
    return 0;
}
