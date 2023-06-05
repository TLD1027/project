#include<stdio.h>
int main(void)
{
    void *ptr1,*ptr2,*ptr3,*ptr4;
    ptr1=malloc(0x420);//smallbin1
    ptr2=malloc(0x10);//fastbin1
    ptr3=malloc(0x10);//fastbin2
    ptr4=malloc(0x420);//smallbin2
    malloc(0x10);//防止与top合并
    free(ptr1);
    *(int *)((long long)ptr4-0x8)=0x430;//修改pre_inuse域
    *(int *)((long long)ptr4-0x10)=0x470;//修改pre_size域
    free(ptr4);//unlink进行前向extend
    malloc(0x150);//占位块

}
