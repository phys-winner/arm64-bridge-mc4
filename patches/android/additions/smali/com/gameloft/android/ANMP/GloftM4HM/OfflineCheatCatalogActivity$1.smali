.class final Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;
.super Ljava/lang/Object;

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field final synthetic a:Landroid/content/Context;

.field public selectedOption:I


# direct methods
.method constructor <init>(Landroid/content/Context;)V
    .locals 1

    iput-object p1, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;->a:Landroid/content/Context;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, -0x1

    iput v0, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;->selectedOption:I

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 1

    packed-switch p2, :options

    return-void

    :option_18
    const/16 v0, 0x12
    goto :purchase

    :option_19
    const/16 v0, 0x13
    goto :purchase

    :option_20
    const/16 v0, 0x14
    goto :purchase

    :option_21
    const/16 v0, 0x15
    goto :purchase

    :option_23
    const/16 v0, 0x17
    goto :purchase

    :option_24
    const/16 v0, 0x18
    goto :purchase

    :option_25
    const/16 v0, 0x19
    goto :purchase

    :option_26
    const/16 v0, 0x1a
    goto :purchase

    :option_27
    const/16 v0, 0x1b
    goto :purchase

    :option_28
    const/16 v0, 0x1c
    goto :purchase

    :option_29
    const/16 v0, 0x1d
    goto :purchase

    :option_30
    const/16 v0, 0x1e
    goto :purchase

    :option_31
    const/16 v0, 0x1f

    :purchase
    iput v0, p0, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatCatalogActivity$1;->selectedOption:I

    return-void

    :options
    .packed-switch 0x0
        :option_18
        :option_19
        :option_20
        :option_21
        :option_23
        :option_24
        :option_25
        :option_26
        :option_27
        :option_28
        :option_29
        :option_30
        :option_31
    .end packed-switch
.end method
