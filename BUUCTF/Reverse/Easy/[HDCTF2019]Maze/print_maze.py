s = "*******+********* ******    ****   ******* **F******    **************"
print(len(s))
for w in (7, 10, 14):
    print("width", w)
    for i in range(0, len(s), w):
        print(s[i:i+w])
    print()
