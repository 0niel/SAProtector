# SAProtector
Python3 Yara Analyzer 
В качестве аргумента запуска указываем путь к файлу. Сиганутры хранятся в папке 'rules', которая должна лежать рядом с .py-файлом.

### Возможности:
- Вывод библиотек импорта и экспорта. Хэш импорта.
- Сканирование с помощью пользовательских YARA сигнатур.
- Статические данные: время компиляции и информация о версии.
- XOR декодирование строк.
- Поиск доменных имен.

``python3 SAProtector.py foo.exe``
