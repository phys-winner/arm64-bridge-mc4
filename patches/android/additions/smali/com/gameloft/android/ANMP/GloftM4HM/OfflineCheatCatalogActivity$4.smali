.class final Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$4;
.super Ljava/lang/Object;

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;

# instance fields
.field final synthetic a:Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity;

# direct methods
.method constructor <init>(Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity;)V
    .locals 0

    iput-object p1, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$4;->a:Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 1

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->resumeGame()V

    iget-object v0, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$4;->a:Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity;

    invoke-virtual {v0}, Landroid/app/Activity;->finish()V

    return-void
.end method
