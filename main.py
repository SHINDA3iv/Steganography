import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox, QComboBox, QSizePolicy
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
from stegano import lsb as steganoLSB
from pystegano import lsb as pysteganoLSB
import stepic
import numpy as np
from PIL import Image


class SteganoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.init_variables()
        self.switch_mode()

    def init_ui(self):
        """Инициализация пользовательского интерфейса."""
        self.setWindowTitle("Steganography Tool")
        self.setGeometry(100, 100, 600, 400)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.create_selector_ui()
        self.create_image_preview_ui()
        self.create_action_ui()

    def init_variables(self):
        """Инициализация переменных."""
        self.input_image_path = ""
        self.output_image_path = "output_image.png"
        self.library_choice = "Stegano"

    def create_selector_ui(self):
        """Создание интерфейса выбора режима и загрузки изображения."""
        self.library_selector = QComboBox()
        self.library_selector.addItems(["Stegano", "Pystegano", "Stepic", "Своя реализация"])
        self.library_selector.currentIndexChanged.connect(self.switch_library)
        self.layout.addWidget(QLabel("Выберите решение:"))
        self.layout.addWidget(self.library_selector)

        self.mode_selector = QComboBox()
        self.mode_selector.addItems(["Кодирование", "Раскодирование"])
        self.mode_selector.currentIndexChanged.connect(self.switch_mode)
        self.layout.addWidget(QLabel("Выберите режим:"))
        self.layout.addWidget(self.mode_selector)

        self.choose_image_button = QPushButton("Выбрать изображение")
        self.choose_image_button.clicked.connect(self.load_image)
        self.layout.addWidget(QLabel("Выберите изображение:"))
        self.layout.addWidget(self.choose_image_button)

    def create_image_preview_ui(self):
        """Создание интерфейса предпросмотра изображения."""
        self.image_preview = QLabel()
        self.image_preview.setMinimumSize(200, 200)
        self.image_preview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.image_preview.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.image_preview)

    def create_action_ui(self):
        """Создание интерфейса ввода сообщений и действий."""
        self.secret_message_input = QLineEdit()
        self.secret_message_input.setPlaceholderText("Введите секретное сообщение...")
        self.layout.addWidget(self.secret_message_input)

        self.action_button = QPushButton()
        self.action_button.clicked.connect(self.perform_action)
        self.layout.addWidget(self.action_button)

    def switch_mode(self):
        """Переключение между режимами кодирования и декодирования."""
        current_mode = self.mode_selector.currentText()
        if current_mode == "Кодирование":
            self.set_encoding_mode()
        elif current_mode == "Раскодирование":
            self.set_decoding_mode()

    def switch_library(self):
        """Переключение между библиотечными решениями и собственной реализацией."""
        self.library_choice = self.library_selector.currentText()

    def set_encoding_mode(self):
        """Настройка интерфейса для режима кодирования."""
        self.secret_message_input.show()
        self.secret_message_input.setPlaceholderText("Введите секретное сообщение...")
        self.action_button.setText("Закодировать сообщение")

    def set_decoding_mode(self):
        """Настройка интерфейса для режима декодирования."""
        self.secret_message_input.hide()
        self.action_button.setText("Раскодировать сообщение")

    def load_image(self):
        """Открытие файла изображения."""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Выберите изображение", "", "Images (*.png *.jpg *.bmp)")
        if file_path:
            self.input_image_path = file_path
            self.update_image_preview()

    def update_image_preview(self):
        """Обновление предпросмотра изображения."""
        if self.input_image_path:
            pixmap = QPixmap(self.input_image_path)
            scaled_pixmap = pixmap.scaled(
                self.image_preview.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            self.image_preview.setPixmap(scaled_pixmap)

    def resizeEvent(self, event):
        """Обновление предпросмотра изображения при изменении размеров окна."""
        super().resizeEvent(event)
        self.update_image_preview()

    def perform_action(self):
        """Выполнение действия в зависимости от режима."""
        if self.mode_selector.currentText() == "Кодирование":
            self.encode_message()
        else:
            self.decode_message()

    def encode_message(self):
        """Кодирование сообщения в изображение."""
        if not self.input_image_path:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите изображение!")
            return

        secret_message = self.secret_message_input.text()
        if not secret_message:
            QMessageBox.warning(self, "Ошибка", "Введите секретное сообщение!")
            return

        try:
            if self.library_choice == "Stegano":
                secret = steganoLSB.hide(self.input_image_path, secret_message)
                secret.save(self.output_image_path)
            elif self.library_choice == "Pystegano":
                image = Image.open(self.input_image_path)
                image_np = np.array(image)
                encoded_image_np = pysteganoLSB.encode(image_np, secret_message)
                encoded_image = Image.fromarray(encoded_image_np)
                encoded_image.save(self.output_image_path)
            elif self.library_choice == "Stepic":
                image = Image.open(self.input_image_path)
                encoded_image = stepic.encode(image, secret_message.encode())
                encoded_image.save(self.output_image_path)
            elif self.library_choice == "Своя реализация":
                self.numpy_pil_hide_message(secret_message)

            QMessageBox.information(self, "Успех", f"Сообщение закодировано в {self.output_image_path}!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось закодировать сообщение: {e}")

    def numpy_pil_hide_message(self, secret_message):
        """Кодирование с использованием numpy и PIL."""
        image = Image.open(self.input_image_path)
        data = np.array(image)

        # Преобразование сообщения в UTF-8
        secret_message_bytes = secret_message.encode('utf-8')
        message_bits = ''.join(format(byte, '08b') for byte in secret_message_bytes) + '00000000'  # Стоп-сигнал

        # Проверка, поместится ли сообщение
        max_bytes = data.size // 8
        if len(message_bits) > max_bytes:
            raise ValueError("Секретное сообщение слишком длинное для этого изображения!")

        # Встраивание сообщения в младшие биты пикселей
        flat_data = data.flatten()
        for i, bit in enumerate(message_bits):
            flat_data[i] = (flat_data[i] & 0xFE) | int(bit)

        # Убедимся, что данные остались в диапазоне uint8
        encoded_data = flat_data.reshape(data.shape).astype(np.uint8)

        # Преобразование обратно в изображение
        encoded_image = Image.fromarray(encoded_data)
        encoded_image.save(self.output_image_path)

    def decode_message(self):
        """Декодирование сообщения из изображения."""
        if not self.input_image_path:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите изображение!")
            return

        try:
            if self.library_choice == "Stegano":
                decoded_message = steganoLSB.reveal(self.input_image_path)
            elif self.library_choice == "Pystegano":
                decoded_message = pysteganoLSB.decode(np.array(Image.open(self.input_image_path)))
            elif self.library_choice == "Stepic":
                decoded_message = stepic.decode(Image.open(self.input_image_path))
            elif self.library_choice == "Своя реализация":
                decoded_message = self.numpy_pil_reveal_message()

            if decoded_message:
                QMessageBox.information(self, "Сообщение", f"Раскодированное сообщение: {decoded_message}")
            else:
                QMessageBox.warning(self, "Ошибка", "Сообщение не найдено!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось раскодировать сообщение: {e}")

    def numpy_pil_reveal_message(self):
        
        """Декодирование с использованием numpy и PIL."""
        image = Image.open(self.input_image_path)
        data = np.array(image)

        # Извлечение младших бит
        flat_data = data.flatten()
        bits = [str(flat_data[i] & 1) for i in range(len(flat_data))]

        # Группировка по 8 бит (1 байт)
        bytes_list = [bits[i:i + 8] for i in range(0, len(bits), 8)]

        # Преобразование в текст
        message_bytes = bytearray()
        for byte in bytes_list:
            char = int(''.join(byte), 2)
            if char == 0:  # Стоп-сигнал
                break
            message_bytes.append(char)
        return message_bytes.decode('utf-8')


def main():
    """Запуск приложения."""
    app = QApplication(sys.argv)
    stegano_app = SteganoApp()
    stegano_app.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
