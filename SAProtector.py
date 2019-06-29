import sys
import os
import socket
import time
import hashlib
import re
import string
import struct
import yara
import pefile

def Main(exe):
  ape = False
  try:
    ape = pefile.PE(exe, fast_load = True)
  except:
    pass
  if ape != False:
    pe          = pefile.PE(exe)
    sample      = ReadSample(exe)
    print('#----- MD5              : ' + str(hashlib.md5(sample).hexdigest()))
    print('#----- SHA1             : ' + str(hashlib.sha1(sample).hexdigest()))
    print('#----- SHA256           : ' + str(hashlib.sha256(sample).hexdigest()))
    print('#----- Хэш импорта      : ' + str(pe.get_imphash()))
    print('#----- Размер файла     : ' + str(len(sample) / 1024))
    print('#----- Major Version    : ' + str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    print('#----- Minor Version    : ' + str(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    print('#----- Дата компиляции  : ' + str(time.strftime('%d/%m/%Y %H:%M:%S', time.gmtime(pe.FILE_HEADER.TimeDateStamp))))

    print('#----- PE Секции      : ')
    for section in pe.sections:
      print('  Название  : ' + str(section.Name))
      print('  Размер  : ' + str(section.SizeOfRawData))
      print('  MD5   : ' + str(section.get_hash_md5()))

      start     = section.PointerToRawData
      endofdata = start + section.SizeOfRawData
      print('')
    print('#----- Импорты -----#')
    try:
      for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
          print('  ' + str(entry.dll) + '!' + str(imp.name))
    except:
      pass
    print('#----- Экспорты -----#')
    try:
      for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print('  ' + str(exp.name))
    except:
      print('  <none>')
      pass

    print('#-----  Сканирование по сигнатурам -----#')
    YaraAnalyze(sample)
    regex = ['[а-яА-ЯёЁa-zA-Z0-9-\s\\\.\:]+\.pdb', \
             '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', \
             '[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})', \
             '[A-z|a-z|0-9]{1,}\.(dll|scr|exe|bat)']

    dhunter_confirm = input("Начать поиск доменных имен? Это может занять время. [yes/no]: ")
    if dhunter_confirm == "yes":
        print('#----- Поиск возможных доменных имен -----#')
        URLfind(sample)

    xor_confirm = input("Начать декодирование возможных строк? Это может занять время. [yes/no]: ")
    if xor_confirm == "yes":
      print('#----- Попытка декодирования интересных строк -----#')
      XorDecoding(sample, regex)

  else:
    sample      = ReadSample(exe)
    print('#----- MD5              : ' + str(hashlib.md5(sample).hexdigest()))
    print('#----- SHA1             : ' + str(hashlib.sha1(sample).hexdigest()))
    print('#----- SHA256           : ' + str(hashlib.sha256(sample).hexdigest()))
    print('#----- Размер файла     : ' + str(len(sample) / 1024))

    print('Это приложение не имеет PE формата.')
    YaraAnalyze(sample)

    regex = ['[а-яА-ЯёЁa-zA-Z0-9-\s\\\.\:]+\.pdb', \
             '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', \
             '[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})', \
             '[A-z|a-z|0-9]{1,}\.(dll|scr|exe|bat)']

    dhunter_confirm = input("Начать поиск доменных имен? Это может занять время. [yes/no]: ")
    if dhunter_confirm == "yes":
      print('#----- Поиск возможных доменных имен -----#')
      URLfind(sample)
    xor_confirm = input("Начать декодирование возможных строк? Это может занять время. [yes/no]: ")
    if xor_confirm == "yes":
      print('#----- Попытка декодирования интересных строк -----#')
      XorDecoding(sample, regex)


def YaraAnalyze(sample):
  directory = os.path.dirname(os.path.abspath(__file__))
  if os.name == 'nt':
    path = directory + '\\rules\\'
  elif os.name == 'posix':
    path = directory + '/'

  for sig in os.listdir(path):
    if sig.endswith('.SAP'):

      f = open(path + sig, 'rb')
      text    = f.read()
      f.close()

      rules   = yara.compile(path + sig)
      matches = rules.match(data=sample)
      for match in matches:
        if match.tags == 'Stealer':
          print('  Обнаружен стиллер: ', str(match),  match.tags)
        print('  Обнаружены сигнатуры: ', str(match), match.tags)


def URLfind(sample):
  regex = re.compile('(?!\.\.)([a-zA-Z0-9_][a-zA-Z0-9\.\-\_]{6,255})\.(com|net|org|co|biz|info|me|us|uk|ca|de|jp|au|fr|ru|ch|it|nl|se|no|es|su|mobi)')
  for key in range(0,0x100):
    if key == 0x20:
      continue
    binary  = xor(sample, key)
    for match in re.finditer(regex, binary):
      s = match.start()
      e = match.end()
      print('  Домен найден по смещению ' + hex(s) + ' с XOR ключем [' + hex(key) + ']: ' + str(binary[s:e]))

def XorDecoding(sample, regex):
  for key in range(1,0x100):
    if key == 0x20:
      continue
    binary = xor(sample, key)

    for entry in regex:
      for match in re.finditer(entry, binary):
        s = match.start()
        e = match.end()
        print('  Строка найдена по смещению ' + hex(s) + ' с XOR ключем [' + hex(key) + '] --> ' + binary[s:e])

def xor(data, key):
  decode = ''
  for d in data:
    decode = decode + chr(d ^ key)
  return decode

def ReadSample(exe):
  f = open(exe,'rb+')
  binary = f.read()
  f.close()
  return binary

if __name__ == "__main__":
  if len(sys.argv) == 2:
    if sys.argv[1] == '-h':
      print('''
        Введите путь к файлу для анализа:
          SAProtector.py filename.exe
            ''')
    else:
      Main(sys.argv[1])
  else:
    print("Требует путь к файлу, который будет проанализирован.")
