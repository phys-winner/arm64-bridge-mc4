.class public final Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;
.super Ljava/lang/Object;


# direct methods
.method private constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static optionForProduct(Ljava/lang/String;)I
    .locals 3

    if-eqz p0, :invalid

    const-string v0, "mc4.cheat."

    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :invalid

    const/16 v0, 0xa

    invoke-virtual {p0, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v0

    :try_start_0
    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    const/16 v1, 0x12

    if-lt v0, v1, :invalid

    const/16 v1, 0x1f

    if-le v0, v1, :check_excluded

    goto :invalid

    :check_excluded
    const/16 v1, 0x16

    if-ne v0, v1, :valid

    goto :invalid

    :catch_0
    :invalid
    const/4 v0, -0x1

    :valid
    return v0
.end method

.method public static isProduct(Ljava/lang/String;)Z
    .locals 1

    invoke-static {p0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->optionForProduct(Ljava/lang/String;)I

    move-result v0

    if-ltz v0, :false

    const/4 v0, 0x1

    return v0

    :false
    const/4 v0, 0x0

    return v0
.end method

.method private static keyForOption(I)Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "owned_"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public static owns(I)Z
    .locals 4

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->getActivityContext()Lcom/gameloft/android/ANMP/GloftM4HM/MC4;

    move-result-object v0

    const-string v1, "MC4OfflineCatalog"

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-static {p0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->keyForOption(I)Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v0

    return v0
.end method

.method public static ensureNative()Z
    .locals 3

    :try_start_0
    const-string v0, "ModernCombat4"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->phase3VfsInstall()V

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatBridge;->gateSelfTest()V

    const-string v1, "MC4OfflineCheats"

    const-string v2, "native libraries loaded"

    nop

    const/4 v0, 0x1

    return v0
    :try_end_0
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_native

    :catch_native
    move-exception v0

    const-string v1, "MC4OfflineCheats"

    invoke-virtual {v0}, Ljava/lang/Throwable;->toString()Ljava/lang/String;

    move-result-object v2

    nop

    const/4 v0, 0x0

    return v0
.end method

.method public static purchase(Ljava/lang/String;)Z
    .locals 5

    invoke-static {p0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->optionForProduct(Ljava/lang/String;)I

    move-result v0

    if-ltz v0, :false

    const-string v1, "MC4OfflineCheats"

    const-string v2, "purchase product accepted"

    nop

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->ensureNative()Z

    move-result v1

    if-eqz v1, :false

    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatBridge;->setEntitlement(I)V

    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatBridge;->apply(I)Z

    move-result v1

    const-string v2, "MC4OfflineCheats"

    const-string v3, "bridge returned"

    nop

    if-eqz v1, :deferred

    goto :persist

    :deferred
    const-string v1, "MC4OfflineCheats"

    const-string v2, "native state not ready; entitlement deferred"

    nop

    :persist
    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->getActivityContext()Lcom/gameloft/android/ANMP/GloftM4HM/MC4;

    move-result-object v1

    const-string v2, "MC4OfflineCatalog"

    const/4 v3, 0x0

    invoke-virtual {v1, v2, v3}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v1

    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v1

    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->keyForOption(I)Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x1

    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object v1

    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->commit()Z

    move-result v1

    return v1

    :false
    const/4 v0, 0x0

    return v0
.end method

.method public static applyOwned()V
    .locals 2

    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->ensureNative()Z

    move-result v1

    if-eqz v1, :done

    const/16 v0, 0x12

    :loop
    const/16 v1, 0x20

    if-ge v0, v1, :done

    const/16 v1, 0x16

    if-ne v0, v1, :check_owned

    add-int/lit8 v0, v0, 0x1

    goto :loop

    :check_owned
    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->owns(I)Z

    move-result v1

    if-eqz v1, :next

    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatBridge;->setEntitlement(I)V

    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatBridge;->apply(I)Z

    :next
    add-int/lit8 v0, v0, 0x1

    goto :loop

    :done
    return-void
.end method

.method public static allowNativeMenu()Z
    .locals 1
    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->ensureNative()Z
    move-result v0
    if-eqz v0, :done
    invoke-static {}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCheatBridge;->gateReady()Z
    move-result v0
    :done
    return v0
.end method

.method public static purchaseAt(I)Z
    .locals 1

    packed-switch p0, :product_switch

    const/4 v0, 0x0

    return v0

    :product_18
    const-string v0, "mc4.cheat.18"

    goto :purchase_product

    :product_19
    const-string v0, "mc4.cheat.19"

    goto :purchase_product

    :product_20
    const-string v0, "mc4.cheat.20"

    goto :purchase_product

    :product_21
    const-string v0, "mc4.cheat.21"

    goto :purchase_product

    :product_23
    const-string v0, "mc4.cheat.23"

    goto :purchase_product

    :product_24
    const-string v0, "mc4.cheat.24"

    goto :purchase_product

    :product_25
    const-string v0, "mc4.cheat.25"

    goto :purchase_product

    :product_26
    const-string v0, "mc4.cheat.26"

    goto :purchase_product

    :product_27
    const-string v0, "mc4.cheat.27"

    goto :purchase_product

    :product_28
    const-string v0, "mc4.cheat.28"

    goto :purchase_product

    :product_29
    const-string v0, "mc4.cheat.29"

    goto :purchase_product

    :product_30
    const-string v0, "mc4.cheat.30"

    goto :purchase_product

    :product_31
    const-string v0, "mc4.cheat.31"

    goto :purchase_product

    :invalid_product
    const/4 v0, 0x0

    return v0

    :purchase_product
    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog;->purchase(Ljava/lang/String;)Z

    move-result v0

    return v0

    :product_switch
    .packed-switch 0x12
        :product_18
        :product_19
        :product_20
        :product_21
        :invalid_product
        :product_23
        :product_24
        :product_25
        :product_26
        :product_27
        :product_28
        :product_29
        :product_30
        :product_31
    .end packed-switch
.end method

.method public static scheduleRetry()V
    .locals 4

    new-instance v0, Landroid/os/Handler;

    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    new-instance v1, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog$1;

    invoke-direct {v1}, Lcom/gameloft/android/ANMP/GloftM4HM/OfflineCatalog$1;-><init>()V

    const-wide/32 v2, 0xea60

    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    return-void
.end method
