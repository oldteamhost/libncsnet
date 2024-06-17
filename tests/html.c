#include "../ncsnet/html.h"

int main(void)
{
  char buf[HTML_BUFLEN];
  memset(&buf, 0, HTML_TAG_MAXLEN);

  html_text_fmt(buf, HTML_TXTSTYLE_BOLD, "kek");
  htmlnl(buf, HTML_TAG_MAXLEN);
  html_text_fmt(buf, HTML_TXTSTYLE_ITALIC, "kek");
  htmlnl(buf, HTML_TAG_MAXLEN);
  html_text_fmt(buf, HTML_TXTSTYLE_STRONG, "kek");    

  htmlnl(buf, HTML_TAG_MAXLEN);
  int kek = 1;
  html_tag_open(buf, "kek", "kdsf=%d class=dev1", kek);
  html_add(buf, HTML_TAG_MAXLEN, "kek");
  html_tag_close(buf, "kek");
  
  printf("%s\n", buf);
  return 0;
}
