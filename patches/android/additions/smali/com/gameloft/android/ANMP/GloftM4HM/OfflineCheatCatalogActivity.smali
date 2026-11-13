.class public Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity;
.super Landroid/app/Activity;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method


# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-static {p0}, Lcom/gameloft/android/ANMP/GloftM4HM/AppData;->guard(Landroid/app/Activity;)Z

    move-result v0

    if-nez v0, :app_data_ready

    return-void

    :app_data_ready

    new-instance v0, Landroid/app/AlertDialog$Builder;

    sget v1, Landroid/R$style;->Theme_Material_Light_Dialog_Alert:I

    invoke-direct {v0, p0, v1}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;I)V

    const-string v1, "Offline cheats — not the original store"

    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    const-string v1, "This is a fan-made offline cheat menu, not a purchase or store. Opening the list changes nothing. Only confirming a selected cheat can change your local save."

    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    const-string v1, "Open manual cheats"

    new-instance v2, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$3;

    invoke-direct {v2, p0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$3;-><init>(Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity;)V

    invoke-virtual {v0, v1, v2}, Landroid/app/AlertDialog$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    const-string v1, "Cancel"

    new-instance v2, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$4;

    invoke-direct {v2, p0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$4;-><init>(Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity;)V

    invoke-virtual {v0, v1, v2}, Landroid/app/AlertDialog$Builder;->setNegativeButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    invoke-virtual {v0}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;

    return-void
.end method

.method public showCatalog()V
    .locals 4

    new-instance v0, Landroid/app/AlertDialog$Builder;

    sget v1, Landroid/R$style;->Theme_Material_Light_Dialog_Alert:I

    invoke-direct {v0, p0, v1}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;I)V

    const-string v1, "Manual Offline Cheats (Not Store)"

    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    const/16 v1, 0xd

    new-array v1, v1, [Ljava/lang/CharSequence;

    const-string v2, "God Mode (18) — LOCAL TEST"
    const/4 v3, 0x0
    aput-object v2, v1, v3

    const-string v2, "Show FPS (19) — LOCAL TEST"
    const/4 v3, 0x1
    aput-object v2, v1, v3

    const-string v2, "Debug Info (20) — LOCAL TEST"
    const/4 v3, 0x2
    aput-object v2, v1, v3

    const-string v2, "Difficulty Unlock (21) — LOCAL TEST"
    const/4 v3, 0x3
    aput-object v2, v1, v3

    const-string v2, "HUD Visibility (23) — LOCAL TEST"
    const/4 v3, 0x4
    aput-object v2, v1, v3

    const-string v2, "Show Debug Maps (24) — LOCAL TEST"
    const/4 v3, 0x5
    aput-object v2, v1, v3

    const-string v2, "Show Nav Mesh (25) — LOCAL TEST"
    const/4 v3, 0x6
    aput-object v2, v1, v3

    const-string v2, "SpeedHack x2 (26) — LOCAL TEST"
    const/4 v3, 0x7
    aput-object v2, v1, v3

    const-string v2, "Infinite Perks (27) — LOCAL TEST"
    const/16 v3, 0x8
    aput-object v2, v1, v3

    const-string v2, "Infinite Killstreaks (28) — LOCAL TEST"
    const/16 v3, 0x9
    aput-object v2, v1, v3

    const-string v2, "Infinite Grenades (29) — LOCAL TEST"
    const/16 v3, 0xa
    aput-object v2, v1, v3

    const-string v2, "Never Reload (30) — LOCAL TEST"
    const/16 v3, 0xb
    aput-object v2, v1, v3

    const-string v2, "Infinite Ammo (31) — LOCAL TEST"
    const/16 v3, 0xc
    aput-object v2, v1, v3

    new-instance v2, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;

    invoke-direct {v2, p0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;-><init>(Landroid/content/Context;)V

    move-object v3, v2

    const/4 v2, -0x1

    invoke-virtual {v0, v1, v2, v3}, Landroid/app/AlertDialog$Builder;->setSingleChoiceItems([Ljava/lang/CharSequence;ILandroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    const-string v1, "Enable selected locally"

    new-instance v2, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$5;

    invoke-direct {v2, v3}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$5;-><init>(Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;)V

    invoke-virtual {v0, v1, v2}, Landroid/app/AlertDialog$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    const-string v1, "Close"

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Landroid/app/AlertDialog$Builder;->setNegativeButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    move-result-object v0

    invoke-virtual {v0}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;

    move-result-object v0

    new-instance v2, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$2;

    invoke-direct {v2, p0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$2;-><init>(Landroid/app/Activity;)V

    invoke-virtual {v0, v2}, Landroid/app/Dialog;->setOnDismissListener(Landroid/content/DialogInterface$OnDismissListener;)V

    return-void
.end method
