.class public final Lcom/gameloft/android/ANMP/GloftM4HM/PlatformBack;
.super Ljava/lang/Object;
.implements Landroid/window/OnBackInvokedCallback;

.field private final activity:Landroid/app/Activity;

.method private constructor <init>(Landroid/app/Activity;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/gameloft/android/ANMP/GloftM4HM/PlatformBack;->activity:Landroid/app/Activity;
    return-void
.end method

.method public static register(Landroid/app/Activity;)Ljava/lang/Object;
    .locals 3

    new-instance v0, Lcom/gameloft/android/ANMP/GloftM4HM/PlatformBack;
    invoke-direct {v0, p0}, Lcom/gameloft/android/ANMP/GloftM4HM/PlatformBack;-><init>(Landroid/app/Activity;)V
    invoke-virtual {p0}, Landroid/app/Activity;->getOnBackInvokedDispatcher()Landroid/window/OnBackInvokedDispatcher;
    move-result-object v1
    const/4 v2, 0x0
    invoke-interface {v1, v2, v0}, Landroid/window/OnBackInvokedDispatcher;->registerOnBackInvokedCallback(ILandroid/window/OnBackInvokedCallback;)V
    return-object v0
.end method

.method public static unregister(Landroid/app/Activity;Ljava/lang/Object;)V
    .locals 1

    check-cast p1, Landroid/window/OnBackInvokedCallback;
    invoke-virtual {p0}, Landroid/app/Activity;->getOnBackInvokedDispatcher()Landroid/window/OnBackInvokedDispatcher;
    move-result-object v0
    invoke-interface {v0, p1}, Landroid/window/OnBackInvokedDispatcher;->unregisterOnBackInvokedCallback(Landroid/window/OnBackInvokedCallback;)V
    return-void
.end method

.method public onBackInvoked()V
    .locals 1

    iget-object v0, p0, Lcom/gameloft/android/ANMP/GloftM4HM/PlatformBack;->activity:Landroid/app/Activity;
    invoke-virtual {v0}, Landroid/app/Activity;->onBackPressed()V
    return-void
.end method
