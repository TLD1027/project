def transform_to_zero(n):
    steps = []
    while n != 0:
        if n % 2 == 0:
            n //= 2
            steps.append('*')
        else:
            n -= 1
            steps.append('+')
    return steps[::-1]

payload = b'0'
payload += b'4'

target = 1936286821
steps = transform_to_zero(target)
for i in steps:
    if i == '+':
        payload += b'6'
    if i == '*':
        payload += b'3'

payload += b'1'
payload += b'4'

target = 1684107883
steps = transform_to_zero(target)
for i in steps:
    if i == '+':
        payload += b'6'
    if i == '*':
        payload += b'3'

print(payload)