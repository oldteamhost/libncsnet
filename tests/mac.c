#include <linux/if_link.h>
#include <stdio.h>
#include <string.h>

#include "../include/base.h"
#include "../include/transport.h"

#define NODESLEN 1400

typedef struct __node {
  int num;
  u8 val[256];
} node;
node *nodes[NODESLEN];
size_t nodes_num=0;

void nodes_open(void);
void nodes_add(const char *str);
void nodes_del(size_t num);
void nodes_mov(size_t from, size_t to);
void nodes_print(void);
void nodes_output(const char *file);
void nodes_free(void);
void fillnode(const char *str, node *n);

void nodes_open(void)
{
  nodes_num=0;
  *nodes=NULL;
}

void nodes_add(const char *str)
{
  node *new=NULL;
  if (!(new=calloc(1, sizeof(node))))
    errx(1, "alloc error\n");
  new->num=0;
  memset(new->val, 0, sizeof(new->val));
  fillnode(str, new);
  nodes[nodes_num]=new;
  nodes_num++;
}

void nodes_del(size_t num)
{
  size_t i;
  /* start 0 */
  num--;
  if (nodes[num]) {
    free(nodes[num]);
    nodes[num]=NULL;
  }
  /* move other elements */
  for (i=num;i<nodes_num-1;i++)
    nodes[i]=nodes[i+1];
  nodes[nodes_num-1]=NULL;
  nodes_num--;
}

void nodes_print(void)
{
  size_t i;
  for (i=0;i<nodes_num;i++) {
    if (nodes[i]) {
      printf("%ld note (%d bits): %s\n", i+1,
      nodes[i]->num, nodes[i]->val);
    }
  }
}

void nodes_output(const char *file)
{
  char res[65535], t[777], err[ERRBUF_MAXLEN];
  size_t i, binlen, ret;
  FILE *f;
  u8 *bin;
  for (i=0;i<nodes_num;i++) {
    snprintf(t, sizeof(t), "%d(%s)%s",
      nodes[i]->num, nodes[i]->val,
      (i==nodes_num-1)?"":",");
    strncat(res, t, sizeof(res)-strlen(res)-1);
    memset(t, 0, sizeof(t));
  }
  bin=frmbuild(&binlen, err, "%s", res);
  if (*err!='\0')
    errx(1, "%s\n", err);
  if (!(f=fopen(file, "wb")))
    errx(1, "%s failed open file\n", file);
  if ((ret=fwrite(bin, sizeof(u8), binlen, f))!=binlen)
    errx(1, "%ld of %ld failed write", ret, binlen);
  fclose(f);
  free(bin);
}

void nodes_mov(size_t from, size_t to)
{
  void *temp;
  size_t i;

  /* start = 0 */
  from--;
  to--;

  if (from>=nodes_num||to>=nodes_num)
    errx(1, "%ld & %ld num error\n", from, to);
  temp=nodes[from];
  if (from<to)
    for (i=from;i<to;i++)
      nodes[i]=nodes[i+1];
  else if (from>to)
    for (i=from;i>to;i--)
      nodes[i]=nodes[i-1];
  nodes[to]=temp;
}

void nodes_free(void)
{
  size_t i;
  for (i=0;i<NODESLEN;i++)
    if (nodes[i])
      free(nodes[i]);
}

void fillnode(const char *str, node *n)
{
#define isspec_c(var, count) \
  ((count!=0)&&(var)[((count)-1)]=='\\')
  size_t l,i,j,o;
  char t[256];
  bool f,p;

  for (l=strlen(str),f=0,i=0;i<l;i++)
    f=(str[i]=='('&&!isspec_c(str, i))?1:f;
  if (!f)
    errx(1, "%s not found (\n", str);
  for (f=0,i=0;i<l;i++)
    f=(str[i]==')'&&!isspec_c(str, i))?1:f;
  if (!f)
    errx(1, "%s not found )\n", str);
  for (p=0,i=j=o=0;i<l;i++) {
    if (str[i]=='('&&!isspec_c(str, i)) {
      if (!o)
        o=i;
      p=1;
      continue;
    }
    if (str[i]==')'&&!isspec_c(str, i))
      break;
    if (p) {
      n->val[j]=str[i];
      j++;
    }
  }
  if (strlen((char*)n->val)<=0)
    errx(1, "%s val vacuus est\n", str);
  for (i=0;i<o;i++) {
    t[i]=str[i];
    if (!isdigit(t[i]))
      errx(1, "%s size only in numbers\n", str);
  }
  n->num=atoi(t);
}

int main(int argc, char **argv)
{
  char cmd[1024];
  size_t l;

  nodes_open();
  for (;;) {
    memset(cmd, 0, sizeof(cmd));
    printf("-> # ");
    fgets(cmd, sizeof(cmd), stdin);
    l=strlen(cmd);
    if (l>0&&cmd[l-1]=='\n')
      cmd[l-1]='\0';
    if (!strcmp(cmd, "help")) {
      printf("add <num>(val);...,  add bytes\n");
      printf("del <num>            delete byte\n");
      printf("mov <from> <to>      move byte\n");
      printf("out <file>           save to bin file\n");
      printf("print, p             print\n");
      printf("exit, quit, q        vihod\n");
      continue;
    }
    if (strstr(cmd, "add")) {
      char *t=NULL;
      t=strtok((cmd+4), ";");
      for (;t;) {
        printf("%s\n", t);
        nodes_add(t);
        t=strtok(NULL, ";");
      }
      continue;
    }
    if (!strcmp(cmd, "print")||!strcmp(cmd, "p")) {
      nodes_print();
      continue;
    }
    if (strstr(cmd, "mov")) {
      size_t from=0, to=0;
      sscanf((cmd+4), "%ld %ld", &from, &to);
      nodes_mov(from, to);
      continue;
    }
    if (strstr(cmd, "del")) {
      size_t num=0;
      sscanf((cmd+4), "%ld", &num);
      nodes_del(num);
      continue;
    }
    if (strstr(cmd, "out")) {
      char file[1024];
      sscanf((cmd+4), "%s", file);
      nodes_output(file);
      continue;
    }
    if (!strcmp(cmd, "exit")||!strcmp(cmd, "quit")||!strcmp(cmd, "q")) {
      nodes_free();
      return 0;
    }
  }

  nodes_output("out");
  return 0;
}
