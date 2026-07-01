# Практическое занятие: Кодинг и уязвимости на Python

---

# ЧАСТЬ 1: ОШИБКИ ВАЛИДАЦИИ ВВОДА

## Демонстрация 1: Опасные функции eval(), exec() и os.system()

**Создайте файл `eval_demo.py`:**

```python
#!/usr/bin/env python3

import os

def dangerous_eval():
    """Демонстрация опасного eval()"""
    user_input = input("Введите математическое выражение: ")
    
    # ОПАСНО! eval() выполняет произвольный код
    result = eval(user_input)
    print(f"Результат: {result}")

def dangerous_exec():
    """Демонстрация опасного exec()"""
    user_input = input("Введите код Python для выполнения: ")
    
    # ОПАСНО! exec() выполняет произвольный код
    exec(user_input)

def dangerous_system():
    """Демонстрация опасного os.system()"""
    user_input = input("Введите команду для выполнения: ")
    
    # ОПАСНО! os.system() выполняет команды shell
    os.system(user_input)

def safe_eval():
    """Безопасная альтернатива eval()"""
    import ast
    user_input = input("Введите число или список: ")
    
    try:
        # БЕЗОПАСНО: только литералы
        result = ast.literal_eval(user_input)
        print(f"Результат: {result}")
    except:
        print("Некорректный ввод")

if __name__ == "__main__":
    print("=== ДЕМОНСТРАЦИЯ ОПАСНЫХ ФУНКЦИЙ ===")
    print()
    print("Примеры опасного ввода:")
    print("  - __import__('os').system('ls')")
    print("  - eval('print(1+1)')")
    print("  - os.system('rm -rf /')")
    print()
    
    # dangerous_eval()  # Раскомментировать для демонстрации
    # dangerous_exec()  # Раскомментировать для демонстрации
    # dangerous_system()  # Раскомментировать для демонстрации
    safe_eval()
```

---

## 🎯 Задание 1: Валидатор пользовательского ввода

**Создайте скрипт `input_validator.py` который:**
- Проверяет пользовательский ввод на наличие опасных паттернов (`__import__`, `eval`, `exec`, `os.system`)
- Проверяет на опасные символы (`;`, `|`, `&`, `$`)
- Возвращает результат валидации
- Очищает ввод от опасных конструкций

---

# ЧАСТЬ 2: PATH TRAVERSAL

## Демонстрация 2: Path Traversal уязвимость

**Создайте файл `path_traversal_demo.py`:**

```python
#!/usr/bin/env python3

import os
from pathlib import Path

# НЕБЕЗОПАСНО: прямое использование пользовательского пути
def unsafe_file_read():
    filename = input("Введите имя файла: ")
    
    try:
        with open(filename, 'r') as f:
            print(f.read())
    except:
        print("Файл не найден")

# НЕБЕЗОПАСНО: попытка обхода директории
def unsafe_traversal():
    filename = input("Введите имя файла (можно использовать ../): ")
    
    try:
        with open(filename, 'r') as f:
            print(f.read())
    except:
        print("Файл не найден")

# БЕЗОПАСНО: проверка пути
def safe_file_read():
    filename = input("Введите имя файла: ")
    
    # Базовый разрешенный каталог
    base_dir = Path("./safe_files")
    base_dir.mkdir(exist_ok=True)
    
    # Создаем безопасный путь
    safe_path = base_dir / os.path.basename(filename)
    
    # Проверяем, что путь внутри разрешенной директории
    try:
        with open(safe_path, 'r') as f:
            print(f.read())
    except FileNotFoundError:
        print("Файл не найден или доступ запрещен")
    except Exception as e:
        print(f"Ошибка: {e}")

def create_test_files():
    """Создание тестовых файлов"""
    os.makedirs("safe_files", exist_ok=True)
    
    test_files = {
        "test.txt": "Это тестовый файл",
        "secret.txt": "Секретная информация!",
        "config.ini": "[database]\npassword=12345",
        "notes.md": "# Заметки\n\nТекст заметок"
    }
    
    for name, content in test_files.items():
        with open(os.path.join("safe_files", name), 'w') as f:
            f.write(content)

if __name__ == "__main__":
    create_test_files()
    
    print("=== PATH TRAVERSAL ДЕМОНСТРАЦИЯ ===")
    print("Файлы в safe_files/: test.txt, secret.txt, config.ini, notes.md")
    print()
    
    print("--- НЕБЕЗОПАСНОЕ ЧТЕНИЕ ---")
    unsafe_file_read()
    
    print("\n--- НЕБЕЗОПАСНОЕ ЧТЕНИЕ С ОБХОДОМ ---")
    unsafe_traversal()
    
    print("\n--- БЕЗОПАСНОЕ ЧТЕНИЕ ---")
    safe_file_read()
```

---

## 🎯 Задание 2: Безопасный файловый менеджер

**Создайте скрипт `secure_file_manager.py` который:**
- Работает только в разрешенной директории
- Проверяет расширения файлов
- Предотвращает Path Traversal
- Ограничивает размер файлов
- Логирует все операции

---

# ЧАСТЬ 3: LFI (LOCAL FILE INCLUSION)

## Демонстрация 3: LFI уязвимость

**Создайте файл `lfi_demo.py`:**

```python
#!/usr/bin/env python3

import os
from pathlib import Path

# НЕБЕЗОПАСНО: прямое включение файла
def unsafe_include():
    filename = input("Введите имя файла для включения: ")
    
    try:
        with open(filename, 'r') as f:
            content = f.read()
            print(f"=== СОДЕРЖИМОЕ {filename} ===")
            print(content)
    except:
        print("Файл не найден")

# НЕБЕЗОПАСНО: включение с обходом
def unsafe_include_traversal():
    filename = input("Введите имя файла (можно использовать ../): ")
    
    try:
        with open(filename, 'r') as f:
            content = f.read()
            print(f"=== СОДЕРЖИМОЕ {filename} ===")
            print(content)
    except:
        print("Файл не найден")

# БЕЗОПАСНО: использование белого списка
def safe_include():
    filename = input("Введите имя файла: ")
    
    # Белый список разрешенных файлов
    ALLOWED_FILES = ['index.html', 'about.html', 'contact.html', 'services.html']
    BASE_DIR = Path("./pages")
    BASE_DIR.mkdir(exist_ok=True)
    
    # Проверка в белом списке
    if filename not in ALLOWED_FILES:
        print(f"❌ Доступ к {filename} запрещен")
        return
    
    # Безопасный путь
    safe_path = BASE_DIR / filename
    
    try:
        with open(safe_path, 'r') as f:
            content = f.read()
            print(f"=== СОДЕРЖИМОЕ {filename} ===")
            print(content)
    except FileNotFoundError:
        print("Файл не найден")

def create_test_pages():
    """Создание тестовых страниц"""
    os.makedirs("pages", exist_ok=True)
    
    test_pages = {
        'index.html': '<h1>Главная</h1><p>Добро пожаловать!</p>',
        'about.html': '<h1>О нас</h1><p>Информация о компании</p>',
        'contact.html': '<h1>Контакты</h1><p>Свяжитесь с нами</p>',
        'services.html': '<h1>Услуги</h1><p>Наши услуги</p>',
        'secret.txt': 'СЕКРЕТНЫЙ ФАЙЛ!',
        'config.php': '<?php $db_pass = "secret_password"; ?>'
    }
    
    for name, content in test_pages.items():
        with open(os.path.join("pages", name), 'w') as f:
            f.write(content)

if __name__ == "__main__":
    create_test_pages()
    
    print("=== LFI ДЕМОНСТРАЦИЯ ===")
    print("Доступные страницы: index.html, about.html, contact.html, services.html")
    print()
    
    print("--- НЕБЕЗОПАСНОЕ ВКЛЮЧЕНИЕ ---")
    unsafe_include()
    
    print("\n--- НЕБЕЗОПАСНОЕ ВКЛЮЧЕНИЕ С ОБХОДОМ ---")
    unsafe_include_traversal()
    
    print("\n--- БЕЗОПАСНОЕ ВКЛЮЧЕНИЕ ---")
    safe_include()
```

---

## 🎯 Задание 3: Безопасный загрузчик страниц

**Создайте скрипт `secure_page_loader.py` который:**
- Разрешает загрузку только из белого списка файлов
- Проверяет расширение файла
- Очищает путь от Path Traversal
- Логирует все попытки доступа
- Возвращает ошибку при нарушении

---
# ЧАСТЬ 4: НЕБЕЗОПАСНАЯ ДЕСЕРИАЛИЗАЦИЯ

## Демонстрация 4: Уязвимость десериализации

**Создайте файл `deserialization_demo.py`:**

```python
#!/usr/bin/env python3

import pickle
import json
import base64

# НЕБЕЗОПАСНО: десериализация пользовательских данных
def unsafe_pickle_deserialize(data):
    obj = pickle.loads(data)
    return obj

# БЕЗОПАСНО: использование JSON
def safe_json_parse(data):
    try:
        obj = json.loads(data)
        return obj
    except:
        return None

# Демонстрация вредоносного pickle
def create_malicious_pickle():
    """Создание вредоносного pickle объекта"""
    import os
    
    # Класс с опасным поведением при десериализации
    class Malicious:
        def __reduce__(self):
            # Выполняет команду при десериализации
            return (os.system, ('echo "ВЗЛОМ!"',))
    
    return pickle.dumps(Malicious())

def main():
    print("=== НЕБЕЗОПАСНАЯ ДЕСЕРИАЛИЗАЦИЯ ===")
    print()
    
    # Демонстрация безопасных данных
    safe_data = json.dumps({"name": "Анна", "age": 25})
    print("1. Безопасные данные (JSON):")
    print(f"   Данные: {safe_data}")
    result = safe_json_parse(safe_data)
    print(f"   Результат: {result}")
    print()
    
    # Демонстрация опасных данных
    print("2. Опасные данные (pickle):")
    malicious = create_malicious_pickle()
    print(f"   Данные: {base64.b64encode(malicious).decode()[:50]}...")
    print("   ⚠️ pickle.loads() может выполнить произвольный код!")
    print()
    
    # Демонстрация пользовательского ввода
    print("3. Проверка пользовательских данных:")
    user_input = input("Введите JSON данные (или 'exit' для выхода): ")
    
    if user_input.lower() != 'exit':
        result = safe_json_parse(user_input)
        if result:
            print(f"✅ Парсинг успешен: {result}")
        else:
            print("❌ Неверный формат JSON")

if __name__ == "__main__":
    main()
```

---

## 🎯 Задание 4: Безопасный парсер данных

**Создайте скрипт `secure_parser.py` который:**
- Принимает JSON строку
- Валидирует структуру (наличие обязательных полей)
- Проверяет типы данных
- Отклоняет небезопасные форматы (pickle, marshal)
- Возвращает ошибку при несоответствии схеме

**Подсказки:**
1. Используйте `json.loads()` для парсинга JSON
2. Проверяйте, что данные являются словарем
3. Проверяйте наличие всех обязательных полей
4. Для каждого поля проверяйте тип данных с помощью `isinstance()`
5. Для строк проверяйте длину
6. Для email проверяйте наличие символа `@`
7. Возвращайте понятные сообщения об ошибках

**Схема для валидации:**
```
{
  "user": {
    "name": str (1-50 символов),
    "age": int (0-150),
    "email": str (содержит @),
    "active": bool
  }
}
```
---

# ЧАСТЬ 5: САМОСТОЯТЕЛЬНАЯ РАБОТА

## 🎯 Задание 5: Анализатор безопасности кода

**Создайте скрипт `code_security_analyzer.py` который:**
1. Принимает на вход путь к `.py` файлу
2. Ищет в коде опасные функции: `eval`, `exec`, `__import__`, `os.system`, `pickle.loads`
3. Ищет потенциальный Path Traversal (открытие файлов с пользовательским путем)
4. Ищет потенциальное LFI (включение файлов с пользовательским путем)
5. Ищет использование `input()` без валидации
6. Генерирует отчет с номерами строк, типом уязвимости, уровнем риска и рекомендацией
