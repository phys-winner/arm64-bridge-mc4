.class final Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$5;
.super Ljava/lang/Object;

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;

# instance fields
.field final synthetic a:Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;

# direct methods
.method constructor <init>(Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;)V
    .locals 0

    iput-object p1, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$5;->a:Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 4

    iget-object v0, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$5;->a:Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;

    iget v1, v0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;->selectedOption:I

    if-ltz v1, :unselected

    invoke-static {v1}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->purchaseAt(I)Z

    move-result v1

    if-eqz v1, :failed

    const-string v2, "Local entitlement applied"

    goto :toast

    :failed
    const-string v2, "Local entitlement failed"

    goto :toast

    :unselected
    const-string v2, "Select a cheat first"

    :toast
    iget-object v0, v0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;->a:Landroid/content/Context;

    const/4 v3, 0x0

    invoke-static {v0, v2, v3}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v0

    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    return-void
.end method
