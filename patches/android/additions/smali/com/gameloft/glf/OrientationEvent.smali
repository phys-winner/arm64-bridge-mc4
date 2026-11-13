.class final Lcom/gameloft/glf/OrientationEvent;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.field private final current:I
.field private final direction:I

.method constructor <init>(II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput p1, p0, Lcom/gameloft/glf/OrientationEvent;->current:I
    iput p2, p0, Lcom/gameloft/glf/OrientationEvent;->direction:I
    return-void
.end method

.method public run()V
    .locals 1

    iget v0, p0, Lcom/gameloft/glf/OrientationEvent;->current:I
    if-ltz v0, :direction
    invoke-static {v0}, Lcom/gameloft/android/ANMP/GloftM4HM/MC4;->setCurrentOrientation(I)V

    :direction
    iget v0, p0, Lcom/gameloft/glf/OrientationEvent;->direction:I
    invoke-static {v0}, Lcom/gameloft/glf/GL2JNILib;->orientationChanged(I)V
    return-void
.end method
