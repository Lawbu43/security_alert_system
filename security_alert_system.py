import RPi.GPIO as GPIO
import serial
import time

# Configuration
SENSOR_PIN = 18  # GPIO pin for motion sensor
PHONE_NUMBER = "+1234567890"  # Replace with recipient's phone number
SERIAL_PORT = "/dev/ttyS0"  # Serial port for SIM800L (adjust as needed)
BAUD_RATE = 9600
ALERT_MESSAGE = "Security Alert: Motion detected!"

# Initialize GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(SENSOR_PIN, GPIO.IN)

# Initialize serial connection to SIM800L
def init_modem():
    modem = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    modem.write('AT\r\n')  # Test modem
    time.sleep(1)
    modem.write('AT+CMGF=1\r\n')  # Set SMS text mode
    time.sleep(1)
    return modem

# Send SMS via SIM800L
def send_sms(modem, phone_number, message):
    modem.write(f'AT+CMGS="{phone_number}"\r\n')
    time.sleep(1)
    modem.write(message + chr(26))  # Message content + Ctrl+Z
    time.sleep(1)
    print(f"SMS sent to {phone_number}")

# Main function
def main():
    modem = init_modem()
    print("Security system started. Waiting for motion...")

    try:
        while True:
            if GPIO.input(SENSOR_PIN):  # Motion detected
                print("Motion detected!")
                send_sms(modem, PHONE_NUMBER, ALERT_MESSAGE)
                time.sleep(60)  # Wait 60 seconds to avoid spamming
            time.sleep(0.1)  # Small delay to reduce CPU usage
    except KeyboardInterrupt:
        print("System stopped.")
    finally:
        modem.close()
        GPIO.cleanup()

if __name__ == "__main__":
    main()
