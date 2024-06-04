#include <stdio.h>
#include "../ncsnet/url.h"

int i = 1;

void test_url(const char *url)
{
  url_t *u = NULL;

  u = url_from_str(url);
  if (!u)
    return;

  char res[url_len(u)];
  url_to_str(u, res, url_len(u));
  printf("probe %s\n", url);
  //  assert(strcmp(url, res) == 0);
  url_print(u);
    
  if (u)
    url_free(u);
}

int main(void)
{
  test_url("ftp://ftp.is.co.za/rfc/rfc1808.txt");
  test_url("sip:911@pbx.mycompany.com");
  test_url("file://Users/John/Documents/Projects/Web/MyWebsite/about.html");
  test_url("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
  test_url("https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#top");
  test_url("https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#:~:text=whatever");
  test_url("tel:+1-816-555-1212");
  test_url("ftp://sdf@gdf.com/");
  test_url("mailto:John.Doe@example.com");
  return 0;
}
