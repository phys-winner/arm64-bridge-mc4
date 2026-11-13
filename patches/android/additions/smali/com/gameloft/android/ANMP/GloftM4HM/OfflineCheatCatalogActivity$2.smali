.class final Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$2;
.super Ljava/lang/Object;

# interfaces
.implements Landroid/content/DialogInterface$OnDismissListener;


# instance fields
.field final synthetic a:Landroid/app/Activity;


# direct methods
.method constructor <init>(Landroid/app/Activity;)V
    .locals 0

    iput-object p1, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$2;->a:Landroid/app/Activity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onDismiss(Landroid/content/DialogInterface;)V
    .locals 1

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->hideloading()V

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->hideloadingGameplay()V

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->resumeGame()V

    iget-object v0, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$2;->a:Landroid/app/Activity;

    invoke-virtual {v0}, Landroid/app/Activity;->finish()V

    return-void
.end method
