/* Battery 7 (17 Nov 2026): transposition layered with a periodic keyed substitution, exact test on the clue letters.
 * Clue positions are PLAINTEXT positions here (this family gives up the in-place reading).
 * Transpositions:
 *   n=97: columnar, width 2..9, every column order, columns read top-down or bottom-up, and the inverse permutation.
 *   n=98 (the "?" before K4 is cipher cell 0, so the plaintext holds one non-letter at pi[0]): columnar width 7 (complete 14x7),
 *         every column order, both read directions, and inverses; K3-style single and double grid turns with widths from {2,7,14,49}.
 * Substitution: periodic key, period 1..13, 8 conventions (plain std/kry x cipher std/kry x vig/beau; var is covered by vig),
 *   key indexed by plaintext position (substitute, then transpose) or by ciphertext position (transpose, then substitute).
 * Flag: key consistent and at least MINRES clue letters left over as a test (default 6, chance about 26^-6 per test).
 * Usage: transpo_periodic [cipher97] [minres] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *STD="ABCDEFGHIJKLMNOPQRSTUVWXYZ", *KRY="KRYPTOSABCDEFGHIJLMNQUVWXZ";
static int ix(const char*a,char c){return (int)(strchr(a,c)-a);}
static char C4[98]; static int ci[2][97], pi_[2][97], kn[24]; static int MINRES=6; static long long nperm=0,ntest=0,nflag=0;
static void test(int n,const int*pi,const char*desc){ /* pi[j]=plain cell at cipher cell j */
  int inv[98]; for(int j=0;j<n;j++) inv[pi[j]]=j; nperm++;
  int q=(n==98)?pi[0]:-1;
  int cj[24],pidx_e[24];
  for(int e=0;e<24;e++){ int i=kn[e]; int ip=(n==98)?(i+(i>=q)):i; cj[e]=inv[ip]; pidx_e[e]=ip; }
  for(int v=0;v<8;v++){ int pa=v>>2,ca=(v>>1)&1,val[24];
    for(int e=0;e<24;e++){ int cl=(n==98)?cj[e]-1:cj[e]; int c=ci[ca][cl],p=pi_[pa][kn[e]]; val[e]=(v&1)?(c+p)%26:(c-p+26)%26; }
    for(int mode=0;mode<2;mode++) for(int p=1;p<=13;p++){ int slot[13]; memset(slot,-1,sizeof slot); int ok=1,used=0; ntest++;
      for(int e=0;e<24&&ok;e++){ int r=(mode?cj[e]:pidx_e[e])%p; if(slot[r]<0){slot[r]=val[e];used++;} else if(slot[r]!=val[e]) ok=0; }
      if(ok&&24-used>=MINRES){ nflag++; printf("FLAG %s | conv=%d mode=%s period=%d residual=%d key=",desc,v,mode?"transpose-then-substitute":"substitute-then-transpose",p,24-used);
        for(int r=0;r<p;r++) putchar(slot[r]<0?'?':(((v>>1)&1)?KRY:STD)[slot[r]]); putchar('\n'); } } } }
static void columnar(int n,int w,const int*sig,int up,int*pi){ int j=0;
  for(int k=0;k<w;k++){ int c=sig[k]; int rows=(n-c+w-1)/w;
    for(int t=0;t<rows;t++){ int r=up?rows-1-t:t; pi[j++]=r*w+c; } } }
static void sweep_columnar(int n,int w){ int sig[14],pi[98],inv[98]; char d[120];
  for(int i=0;i<w;i++) sig[i]=i;
  for(;;){
    for(int up=0;up<2;up++){ columnar(n,w,sig,up,pi);
      if(n==97||pi[0]>=0){ sprintf(d,"n=%d columnar w=%d up=%d order=",n,w,up); for(int i=0;i<w;i++) sprintf(d+strlen(d),"%d",sig[i]); test(n,pi,d);
        for(int j=0;j<n;j++) inv[pi[j]]=j; strcat(d," INVERSE"); test(n,inv,d); } }
    int i=w-2; while(i>=0&&sig[i]>sig[i+1]) i--; if(i<0) break; int j=w-1; while(sig[j]<sig[i]) j--; int t=sig[i];sig[i]=sig[j];sig[j]=t;
    for(int a=i+1,b=w-1;a<b;a++,b--){t=sig[a];sig[a]=sig[b];sig[b]=t;} } }
static void turn(int n,int w,int style,const int*in,int*out){ /* write `in` row-major width w, read columns; style bit0: columns right-to-left, bit1: bottom-up */
  int R=n/w,j=0; for(int k=0;k<w;k++){ int c=(style&1)?w-1-k:k; for(int t=0;t<R;t++){ int r=(style&2)?R-1-t:t; out[j++]=in[r*w+c]; } } }
int main(int argc,char**argv){
  strcpy(C4,argc>1?argv[1]:"OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"); if(argc>2) MINRES=atoi(argv[2]);
  const char*c1="EASTNORTHEAST",*c2="BERLINCLOCK"; int nk=0; char PL[97]={0};
  for(int j=0;j<13;j++) PL[21+j]=c1[j]; for(int j=0;j<11;j++) PL[63+j]=c2[j];
  for(int i=0;i<97;i++){ ci[0][i]=ix(STD,C4[i]); ci[1][i]=ix(KRY,C4[i]); if(PL[i]){kn[nk++]=i; pi_[0][i]=ix(STD,PL[i]); pi_[1][i]=ix(KRY,PL[i]);} }
  for(int w=2;w<=9;w++) sweep_columnar(97,w);
  sweep_columnar(98,7); sweep_columnar(98,2);
  int ws[4]={2,7,14,49}, id[98],a[98],b[98],inv[98]; char d[120]; for(int i=0;i<98;i++) id[i]=i;
  for(int w1=0;w1<4;w1++) for(int s1=0;s1<4;s1++){ turn(98,ws[w1],s1,id,a); sprintf(d,"n=98 turn w=%d style=%d",ws[w1],s1); test(98,a,d);
    for(int j=0;j<98;j++) inv[a[j]]=j; strcat(d," INVERSE"); test(98,inv,d);
    for(int w2=0;w2<4;w2++) for(int s2=0;s2<4;s2++){ turn(98,ws[w2],s2,a,b); sprintf(d,"n=98 turns w=%d style=%d then w=%d style=%d",ws[w1],s1,ws[w2],s2); test(98,b,d);
      for(int j=0;j<98;j++) inv[b[j]]=j; strcat(d," INVERSE"); test(98,inv,d); } }
  printf("permutations=%lld tests=%lld flagged=%lld minres=%d\n",nperm,ntest,nflag,MINRES); return 0; }
