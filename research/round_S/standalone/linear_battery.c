/* K4 in-place linear key-model battery (17 Nov 2026).
 * Hypothesis class: cipher index = (+/-) plain index + K_i (mod 26) in declared alphabets, with
 *   K_i = A[(i) mod p] + B[(i) mod q]  or  A[i mod p] + R[(i+o) div w]
 *         (+ beta*i) (+ alpha*X_{i-L})  with X = plaintext, ciphertext or key index at lag L.
 * All coefficients/keys unknown in Z26. Exact test: linear consistency mod 2 and mod 13 on the 24 known positions.
 * Usage: linear_battery <cipher97> [seed-for-planted-or-0]  ; prints flagged models.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#define N 97
static const char *STD="ABCDEFGHIJKLMNOPQRSTUVWXYZ", *KRY="KRYPTOSABCDEFGHIJLMNQUVWXZ";
static int idx(const char*a,char c){return (int)(strchr(a,c)-a);}
static char C4[N+1]; static int known[24], nk=0; static char PL[N];
static int pidx[2][N], cidx[2][N];           /* [alphabet][pos], -1 unknown */
static int T[8][N];                          /* key index per convention at known positions */
static const char* cname[8]={"Pstd/Cstd/vig","Pstd/Cstd/beau","Pstd/Ckry/vig","Pstd/Ckry/beau","Pkry/Cstd/vig","Pkry/Cstd/beau","Pkry/Ckry/vig","Pkry/Ckry/beau"};
static double THRESH=7.5; static long long ntests=0, nflag=0, ndec=0, ncons=0;
#define MAXC 96
/* eliminate mod m; M has ne rows, nc unknown cols + nr rhs cols. returns rank; cons[r]=1 if rhs r consistent */
static int elim(int m,int ne,int nc,int nr,int M[][MAXC+12],int *cons){
  static int inv13[13]={0,1,7,9,10,8,11,2,5,3,4,6,12};
  int rank=0;
  for(int c=0;c<nc&&rank<ne;c++){
    int piv=-1; for(int r=rank;r<ne;r++) if(M[r][c]%m){piv=r;break;}
    if(piv<0) continue;
    if(piv!=rank){ for(int k=c;k<nc+nr;k++){int t=M[piv][k];M[piv][k]=M[rank][k];M[rank][k]=t;} }
    int iv = (m==2)?1:inv13[M[rank][c]%m];
    for(int k=c;k<nc+nr;k++) M[rank][k]=(M[rank][k]*iv)%m;
    for(int r=rank+1;r<ne;r++){ int f=M[r][c]%m; if(f) for(int k=c;k<nc+nr;k++) M[r][k]=((M[r][k]-f*M[rank][k])%m+m)%m; }
    rank++;
  }
  for(int j=0;j<nr;j++){ cons[j]=1; for(int r=rank;r<ne;r++) if(M[r][nc+j]%m){cons[j]=0;break;} }
  return rank;
}
typedef struct { int type,L,alph; } Auto;   /* type 0 none,1 P,2 C,3 K */
static void run_model(const char*base,int ncb,int colsb[][3],int ncolsb, int prog, Auto a, Auto a2){
  /* colsb[e][j]: for known equation e, column index of base component j (ncolsb comps), total ncb base columns */
  for(int convloop=0; convloop<((a.type==3||a2.type==3)?8:1); convloop++){
    static int M2[24][MAXC+12], M13[24][MAXC+12];
    int ne=0, nc=ncb+prog+(a.type?1:0)+(a2.type?1:0); int nr=(a.type==3||a2.type==3)?1:8;
    if(nc>MAXC) return;
    for(int e=0;e<nk;e++){
      int i=known[e]; int av=0,av2=0;
      Auto as[2]={a,a2}; int vals[2]={0,0}; int ok=1;
      for(int z=0;z<2;z++){ Auto x=as[z]; if(!x.type) continue; int j=i-x.L; if(j<0){ok=0;break;}
        if(x.type==1){ if(pidx[x.alph][j]<0){ok=0;break;} vals[z]=pidx[x.alph][j]; }
        else if(x.type==2){ vals[z]=cidx[x.alph][j]; }
        else { if(pidx[0][j]<0){ok=0;break;} vals[z]=T[convloop][j]; } }
      if(!ok) continue; av=vals[0]; av2=vals[1];
      int *r2=M2[ne], *r13=M13[ne]; memset(r2,0,sizeof(int)*(nc+nr)); memset(r13,0,sizeof(int)*(nc+nr));
      for(int j=0;j<ncolsb;j++){ r2[colsb[e][j]]=1; r13[colsb[e][j]]=1; }
      int c=ncb; if(prog){ r2[c]=i%2; r13[c]=i%13; c++; }
      if(a.type){ r2[c]=av%2; r13[c]=av%13; c++; } if(a2.type){ r2[c]=av2%2; r13[c]=av2%13; c++; }
      for(int v=0;v<nr;v++){ int t=T[nr==1?convloop:v][i]; r2[nc+v]=t%2; r13[nc+v]=t%13; }
      ne++;
    }
    if(ne<8) return;
    int c2[8],c13[8]; int k2=elim(2,ne,nc,nr,M2,c2), k13=elim(13,ne,nc,nr,M13,c13);
    double score=(ne-k2)*log10(2.0)+(ne-k13)*log10(13.0);
    for(int v=0;v<nr;v++){ ntests++; if(score>=THRESH) ndec++; if(c2[v]&&c13[v]) ncons++;
      if(c2[v]&&c13[v]&&score>=THRESH){ nflag++;
        printf("FLAG %s | %s prog=%d auto=(%d,L%d,a%d) auto2=(%d,L%d,a%d) eq=%d rank2=%d rank13=%d score=%.1f\n",
          cname[nr==1?convloop:v],base,prog,a.type,a.L,a.alph,a2.type,a2.L,a2.alph,ne,k2,k13,score); } }
  }
}
int main(int argc,char**argv){
  strcpy(C4, argc>1?argv[1]:"OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR");
  if(argc>2) THRESH=atof(argv[2]);
  memset(PL,0,sizeof PL); const char*c1="EASTNORTHEAST",*c2="BERLINCLOCK";
  for(int j=0;j<13;j++) PL[21+j]=c1[j]; for(int j=0;j<11;j++) PL[63+j]=c2[j];
  for(int i=0;i<N;i++){ cidx[0][i]=idx(STD,C4[i]); cidx[1][i]=idx(KRY,C4[i]);
    if(PL[i]){ known[nk++]=i; pidx[0][i]=idx(STD,PL[i]); pidx[1][i]=idx(KRY,PL[i]); } else pidx[0][i]=pidx[1][i]=-1; }
  for(int i=0;i<N;i++) if(PL[i]) for(int pa=0;pa<2;pa++) for(int ca=0;ca<2;ca++){
      T[pa*4+ca*2+0][i]=((cidx[ca][i]-pidx[pa][i])%26+26)%26; T[pa*4+ca*2+1][i]=(cidx[ca][i]+pidx[pa][i])%26; }
  /* auto options */
  static Auto autos[400]; int na=0; autos[na++]=(Auto){0,0,0};
  for(int al=0;al<2;al++){ for(int L=1;L<=52;L++){ if(L>12&&L<30) continue; autos[na++]=(Auto){1,L,al}; }
                           for(int L=1;L<=73;L++) autos[na++]=(Auto){2,L,al}; }
  for(int L=1;L<=52;L++){ if(L>12&&L<30) continue; autos[na++]=(Auto){3,L,0}; }
  static int cols[24][3]; char base[80];
  for(int prog=0;prog<2;prog++) for(int ai=0;ai<na;ai++){
    Auto a=autos[ai];
    /* optional second auto: same lag, other source, or none */
    Auto seconds[6]; int ns=0; seconds[ns++]=(Auto){0,0,0};
    if(a.type==1){ for(int al=0;al<2;al++) seconds[ns++]=(Auto){2,a.L,al}; }
    for(int si=0;si<ns;si++){ Auto a2=seconds[si];
      for(int p=1;p<=26;p++){
        for(int q=p+1;q<=26;q++){ if(p==1&&0) continue;
          for(int e=0;e<nk;e++){ cols[e][0]=known[e]%p; cols[e][1]=p+known[e]%q; }
          sprintf(base,"PER(%d)+PER(%d)",p,q); run_model(base,p+q,cols,2,prog,a,a2); }
        for(int w=2;w<=49;w++) for(int o=0;o<2;o++){
          for(int e=0;e<nk;e++){ cols[e][0]=known[e]%p; cols[e][1]=p+(known[e]+o)/w; }
          sprintf(base,"PER(%d)+ROW(w%d,o%d)",p,w,o); run_model(base,p+(N+o)/w+1,cols,2,prog,a,a2); }
        /* physical sculpture rows: 0-3, 4-34, 35-65, 66-96 ; plus column key by physical column */
        for(int e=0;e<nk;e++){ int i=known[e]; cols[e][0]=i%p; cols[e][1]=p+(i<4?0:1+(i-4)/31); }
        sprintf(base,"PER(%d)+PHYSROW",p); run_model(base,p+4,cols,2,prog,a,a2);
        for(int e=0;e<nk;e++){ int i=known[e]; cols[e][0]=i%p; cols[e][1]=p+(i<4?27+i:(i-4)%31); cols[e][2]=p+31+(i<4?0:1+(i-4)/31); }
        sprintf(base,"PER(%d)+PHYSCOL+PHYSROW",p); run_model(base,p+35,cols,3,prog,a,a2);
      }
    }
  }
  printf("tests=%lld decidable=%lld consistent_any_score=%lld flagged=%lld threshold=%.1f\n",ntests,ndec,ncons,nflag,THRESH);
  return 0;
}
