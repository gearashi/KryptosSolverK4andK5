/* K4 in-place linear battery 2 (17 Nov 2026): unknown mixed alphabets as linear unknowns.
 * Position-preserving model:  LHS-unknown terms summed (mod 26) = RHS known index.
 *   mode A  S[p_i] + (terms) = idx_ca(c_i)          unknown plaintext alphabet S, cipher alphabet ca in {std,kry}
 *   mode B  U[c_i] + (terms) = idx_pa(p_i)          unknown cipher alphabet U, plain alphabet pa in {std,kry}
 *   mode D  (terms) = idx_ca(c_i) -/+ idx_pa(p_i)    8 fixed conventions
 * terms = PER(p) [+ one of PER(q) | ROW(w,o) | ROWLIN(w,o) | PHYSROW] [+ PROG] [+ one auto term]
 * auto  = fixed-alphabet plaintext/ciphertext lag L (one unknown multiplier) or unknown-alphabet lag term (26 unknowns).
 * Exact test: consistency mod 2 and mod 13. score = residual equations in decimal digits; flag when consistent and score >= THRESH.
 * Usage: linear_battery2 [cipher97] [thresh] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#define N 97
#define W 200
static const char *STD="ABCDEFGHIJKLMNOPQRSTUVWXYZ", *KRY="KRYPTOSABCDEFGHIJLMNQUVWXZ";
static int idx(const char*a,char c){return (int)(strchr(a,c)-a);}
static char C4[N+1], PL[N]; static int known[24], nk=0, pidx[2][N], cidx[2][N];
static double THRESH=7.5; static long long ntests=0,nflag=0,ndec=0;
enum {T_PER,T_ROW,T_ROWLIN,T_PHYSROW,T_PROG,T_PLET,T_CLET,T_PAF,T_CAF,T_PAU,T_CAU,T_NONE};
typedef struct {int k,a,b;} Term;
static int ncol(Term t){ switch(t.k){case T_PER:return t.a; case T_ROW:return (N+t.b)/t.a+1; case T_PHYSROW:return 4;
  case T_PLET: case T_CLET: case T_PAU: case T_CAU: return 26; case T_NONE: return 0; default: return 1;} }
/* returns 0 if not available at position i; else sets col (relative) and coef */
static int term(Term t,int i,int*col,int*coef){ *coef=1; *col=0; int j;
  switch(t.k){
    case T_PER: *col=i%t.a; return 1;
    case T_ROW: *col=(i+t.b)/t.a; return 1;
    case T_ROWLIN: *coef=(i+t.b)/t.a; return 1;
    case T_PHYSROW: *col=i<4?0:1+(i-4)/31; return 1;
    case T_PROG: *coef=i; return 1;
    case T_PLET: *col=pidx[0][i]; return 1;
    case T_CLET: *col=cidx[0][i]; return 1;
    case T_PAF: j=i-t.a; if(j<0||pidx[0][j]<0) return 0; *coef=pidx[t.b][j]; return 1;
    case T_CAF: j=i-t.a; if(j<0) return 0; *coef=cidx[t.b][j]; return 1;
    case T_PAU: j=i-t.a; if(j<0||pidx[0][j]<0) return 0; *col=pidx[0][j]; return 1;
    case T_CAU: j=i-t.a; if(j<0) return 0; *col=cidx[0][j]; return 1;
  } return 0; }
static const char* tn[]={"PER","ROW","ROWLIN","PHYSROW","PROG","PLET","CLET","PAUTOfixed","CAUTOfixed","PAUTOunk","CAUTOunk","-"};
static int elim(int m,int ne,int nc,int nr,int M[][W],int *cons){
  static int inv13[13]={0,1,7,9,10,8,11,2,5,3,4,6,12}; int rank=0;
  for(int c=0;c<nc&&rank<ne;c++){ int piv=-1; for(int r=rank;r<ne;r++) if(M[r][c]%m){piv=r;break;}
    if(piv<0) continue;
    if(piv!=rank) for(int k=c;k<nc+nr;k++){int t=M[piv][k];M[piv][k]=M[rank][k];M[rank][k]=t;}
    int iv=(m==2)?1:inv13[M[rank][c]%m];
    for(int k=c;k<nc+nr;k++) M[rank][k]=(M[rank][k]*iv)%m;
    for(int r=rank+1;r<ne;r++){int f=M[r][c]%m; if(f) for(int k=c;k<nc+nr;k++) M[r][k]=((M[r][k]-f*M[rank][k])%m+m)%m;}
    rank++; }
  for(int j=0;j<nr;j++){cons[j]=1; for(int r=rank;r<ne;r++) if(M[r][nc+j]%m){cons[j]=0;break;}}
  return rank; }
static void run(int mode,Term*ts,int nt){
  static int M2[24][W],M13[24][W]; int off[8],tot=0; for(int j=0;j<nt;j++){off[j]=tot; tot+=ncol(ts[j]);}
  static int map[400]; for(int c=0;c<tot;c++) map[c]=-1; int nc=0, ne=0; int nr=(mode==2)?8:2;
  static int ec[24][8],ef[24][8],ei[24];
  for(int e=0;e<nk;e++){ int i=known[e],ok=1; for(int j=0;j<nt;j++){int c,f; if(!term(ts[j],i,&c,&f)){ok=0;break;} ec[ne][j]=off[j]+c; ef[ne][j]=f;} if(!ok) continue;
    for(int j=0;j<nt;j++) if(map[ec[ne][j]]<0) map[ec[ne][j]]=nc++; ei[ne]=i; ne++; }
  if(ne<8||nc+nr>W) return;
  { int rb=nc-3; if(rb<0) rb=0; if(rb>ne) rb=ne; /* rank is at most nc; shared constants can lower it by up to 3 */
    if((ne-rb)*1.415<THRESH-0.01){ ntests+=nr; return; } }
  for(int e=0;e<ne;e++){ memset(M2[e],0,sizeof(int)*(nc+nr)); memset(M13[e],0,sizeof(int)*(nc+nr));
    for(int j=0;j<nt;j++){int c=map[ec[e][j]]; M2[e][c]=(M2[e][c]+ef[e][j])%2; M13[e][c]=(M13[e][c]+ef[e][j])%13;}
    int i=ei[e];
    for(int v=0;v<nr;v++){ int t;
      if(mode==0) t=cidx[v][i]; else if(mode==1) t=pidx[v][i];
      else { int pa=v>>2, ca=(v>>1)&1; t=(v&1)?(cidx[ca][i]+pidx[pa][i])%26:((cidx[ca][i]-pidx[pa][i])%26+26)%26; }
      M2[e][nc+v]=t%2; M13[e][nc+v]=t%13; } }
  int c2[8],c13[8]; int k2=elim(2,ne,nc,nr,M2,c2),k13=elim(13,ne,nc,nr,M13,c13);
  double score=(ne-k2)*log10(2.0)+(ne-k13)*log10(13.0);
  for(int v=0;v<nr;v++){ ntests++; if(score>=THRESH) ndec++;
    if(c2[v]&&c13[v]&&score>=THRESH){ nflag++; printf("FLAG mode=%c rhs=%d |",'A'+(mode==2?3:mode),v);
      for(int j=0;j<nt;j++) printf(" %s(%d,%d)",tn[ts[j].k],ts[j].a,ts[j].b);
      printf(" | eq=%d cols=%d rank2=%d rank13=%d score=%.1f\n",ne,nc,k2,k13,score);} } }
int main(int argc,char**argv){
  strcpy(C4,argc>1?argv[1]:"OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR");
  if(argc>2) THRESH=atof(argv[2]);
  memset(PL,0,sizeof PL); const char*c1="EASTNORTHEAST",*c2="BERLINCLOCK";
  for(int j=0;j<13;j++) PL[21+j]=c1[j]; for(int j=0;j<11;j++) PL[63+j]=c2[j];
  for(int i=0;i<N;i++){cidx[0][i]=idx(STD,C4[i]);cidx[1][i]=idx(KRY,C4[i]);
    if(PL[i]){known[nk++]=i;pidx[0][i]=idx(STD,PL[i]);pidx[1][i]=idx(KRY,PL[i]);} else pidx[0][i]=pidx[1][i]=-1;}
  static Term sec[400]; int ns=0; sec[ns++]=(Term){T_NONE,0,0}; sec[ns++]=(Term){T_PHYSROW,0,0};
  for(int w=2;w<=49;w++) for(int o=0;o<2;o++){ sec[ns++]=(Term){T_ROW,w,o}; sec[ns++]=(Term){T_ROWLIN,w,o}; }
  static Term au[600]; int na=0; au[na++]=(Term){T_NONE,0,0};
  for(int L=1;L<=75;L++){ for(int al=0;al<2;al++){au[na++]=(Term){T_PAF,L,al}; au[na++]=(Term){T_CAF,L,al};} au[na++]=(Term){T_PAU,L,0}; au[na++]=(Term){T_CAU,L,0}; }
  for(int mode=0;mode<3;mode++) for(int p=1;p<=26;p++) for(int si=0;si<ns+26;si++) for(int prog=0;prog<2;prog++) for(int ai=0;ai<na;ai++){
    Term ts[8]; int nt=0;
    if(mode==0) ts[nt++]=(Term){T_PLET,0,0}; if(mode==1) ts[nt++]=(Term){T_CLET,0,0};
    ts[nt++]=(Term){T_PER,p,0};
    Term s; if(si<ns) s=sec[si]; else { int q=si-ns+1; if(q<=p) continue; s=(Term){T_PER,q,0}; }
    if(s.k!=T_NONE) ts[nt++]=s; if(prog) ts[nt++]=(Term){T_PROG,0,0}; if(au[ai].k!=T_NONE) ts[nt++]=au[ai];
    run(mode,ts,nt); }
  printf("tests=%lld decidable=%lld flagged=%lld threshold=%.1f\n",ntests,ndec,nflag,THRESH); return 0; }
