################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../capture.c \
../iprestrict.c \
../parse.c \
../subinterface.c 

OBJS += \
./capture.o \
./iprestrict.o \
./parse.o \
./subinterface.o 

C_DEPS += \
./capture.d \
./iprestrict.d \
./parse.d \
./subinterface.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


