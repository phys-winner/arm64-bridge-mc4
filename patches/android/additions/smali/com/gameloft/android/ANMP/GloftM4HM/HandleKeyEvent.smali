.class final Lcom/gameloft/android/ANMP/GloftM4HM/HandleKeyEvent;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.field private final activity:Lcom/gameloft/android/ANMP/GloftM4HM/MC4;
.field private final key:I

.method constructor <init>(Lcom/gameloft/android/ANMP/GloftM4HM/MC4;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/gameloft/android/ANMP/GloftM4HM/HandleKeyEvent;->activity:Lcom/gameloft/android/ANMP/GloftM4HM/MC4;
    iput p2, p0, Lcom/gameloft/android/ANMP/GloftM4HM/HandleKeyEvent;->key:I
    return-void
.end method

.method public run()V
    .locals 2

    iget-object v0, p0, Lcom/gameloft/android/ANMP/GloftM4HM/HandleKeyEvent;->activity:Lcom/gameloft/android/ANMP/GloftM4HM/MC4;
    iget v1, p0, Lcom/gameloft/android/ANMP/GloftM4HM/HandleKeyEvent;->key:I
    invoke-virtual {v0, v1}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->nativeHandleKey(I)V
    return-void
.end method
