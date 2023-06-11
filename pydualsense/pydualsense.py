import logging
import os
import sys
from sys import platform
import json
import math

if platform.startswith('Windows') and sys.version_info >= (3, 8):
    os.add_dll_directory(os.getcwd())

# import hidapi
import hid
from .src.enums import (LedOptions, PlayerID, PulseOptions, TriggerModes, Brightness, ConnectionType, BatteryState) # type: ignore
import threading
# from .src.event_system import Event
from .src.checksum import compute
from copy import deepcopy

# ... Make sure this isn't needed for controlling the controller
# EVENT_SYSTEM = False

logger = logging.getLogger()
# FORMAT = '%(asctime)s %(message)s'
FORMAT = '%(message)s'
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

class pydualsense:
    def __init__(self, verbose: bool = False):
        """
        initialise the library but dont connect to the controller
        Args:
            verbose (bool, optional): display verbose out (debug prints of input and output). Defaults to False.
        """
        # TODO: maybe add a init function to not automatically
        # allocate controller when class is declared(???????)        
        self.verbose = verbose
        if self.verbose:
            logger.setLevel(logging.DEBUG)


    def to_object(self):
        return json.dumps(
            self.state,
            default=lambda o: o.__dict__,
            sort_keys=False,
            indent=None,
            # separators=(',', ':') # condenses, but node can't read it
    )

    def init(self):
        "initialize module and device states. Starts the sendReport background thread at the end"
        self.device = self.get_device()
        self.set_block_state(False); # uh, this works? blockState to true does not. 
        self.connection_type = self.get_connection_type()

        # controller states
        self.state = DSState() 
        self.last_states = None
        self.current_state = None

        # Things we can tell the controller to do
        # shouldn't we have these in the state.. even if they're settable....
        self.lrumble = 0
        self.l2force = DSTrigger() # left trigger
        
        self.rrumble = 0
        self.r2force = DSTrigger() # right trigger

        # Need to pull these out
        self.light = DSLight() # control led light of ds
        self.audio = DSAudio() # ds audio setting
        self.battery = DSBattery()

        self.ds_thread = True        
        self.report_thread = threading.Thread(target=self.sendReport)
        self.report_thread.start()

    def set_block_state(self, s) -> bool:
        # https://github.com/trezor/cython-hidapi/blob/a4e83fc199dc582157fe1f31a2c1c97d4fcdda3b/chid.pxd#L31
        # --> lib that hid duses: https://github.com/hyperdivision/hid#hidset_nonblockingdevice-nonblock
        # In non-blocking mode calls to hid.read() will return immediately with a
        # value of 0 if there is no data to be read. In blocking mode, hid.read()
        # will wait (block) until there is data to read before returning.        
        # Nonblocking can be turned on and off at any time.
        if s == True:
            self.device.set_nonblocking(1)
        else:
            self.device.set_nonblocking(0);


    def get_connection_type(self) -> ConnectionType:
        """
        We ask the controller for an input report with a length up to 100 bytes
        and afterwords check the lenght of the received input report.
        The connection type determines the length of the report.
        This way of determining is not pretty but it works..
        """        
        dummy_report = self.device.read(100)
        input_report_length = len(dummy_report)
        self.input_report_length = 78
        self.output_report_length = 78
        
        if input_report_length == 64:
            self.input_report_length = 64
            self.output_report_length = 64
            return ConnectionType.USB
        elif input_report_length == 78:
            self.input_report_length = 78
            self.output_report_length = 78
            return ConnectionType.BT

    def close(self) -> None:
        "Stops the report thread and closes the HID device"
        # TODO: reset trigger effect to default
        self.ds_thread = False
        self.report_thread.join()
        self.device.close()

    def get_device(self) -> hid.device:
        """
        find HID dualsense device and open it
        Raises:
            Exception: HIDGuardian detected
            Exception: No device detected
        Returns:
            hid.Device: returns opened controller device
        """
        # TODO: detect connection mode, bluetooth has a bigger write buffer
        # TODO: implement multiple controllers working
        if sys.platform.startswith('win32'):
            import pydualsense.hidguardian as hidguardian
            if hidguardian.check_hide():
                raise Exception('HIDGuardian detected. Delete the controller from HIDGuardian and restart PC to connect to controller')

        detected_device: hid.device = None
        devices = hid.enumerate(vendor_id=0x054c)
        for device in devices:
            if device['vendor_id'] == 0x054C and device['product_id'] == 0x0CE6:
                detected_device = device
        if detected_device is None:
            raise Exception('No device detected')    
        dual_sense = hid.device();
        dual_sense.open(vendor_id=detected_device['vendor_id'], product_id=detected_device['product_id'])
        return dual_sense

    def set_led_touchpad_color(self, r, g, b) -> bool:
        # [r, g, b]
        self.light.led_touchpad_color = [math.floor(r), math.floor(g), math.floor(b)];

    def set_led_options(self, opt) -> bool:
        # off, playerledbrightness, uninterruptableled, both
        # 0x0, 0x1, 0x2, 0x1 | 0x02         
        self.light.led_options = opt

    def set_led_pulse_options(self, opt):
        # off, fadeblue, fadeout,
        # 0x0, 0x1, 0x2
        self.light.led_pulse_options = opt

    def set_led_player_brightness(self, brightness):
        # high, medium, low
        # 0x0, 0x1, 0x2        
        self.light.led_player_brightness = led_player_brightness

    def set_led_player_number(self, num):
        """
        Sets the PlayerID of the controller with the choosen LEDs.
        (The controller has 4 Player states)
        """
        # 4, 10, 21, 27, 31
        # 0x4, 0xA, 0x5F, 0xBF, 0xEF
        self.light.led_player_number = num
        
    def set_lrumble(self, n) -> bool:
        if (n < 0 or n > 255):
            return False
        self.lrumble = math.floor(n)
        
    def set_rrumble(self, n) -> bool:
        if (n < 0 or n > 255):
            return False
        self.rrumble = math.floor(n)

    def sendReport(self) -> None:
        """background thread handling the reading of the device and updating its states
        """
        while self.ds_thread:
            # read data from the input report of the controller
            inReport = self.device.read(self.input_report_length)
            # inReport = self.device.read(78)

            # [self] decrypt the packet and bind the inputs
            # self.c = self.decrypt(inReport)

            self.readControllerBytes(inReport)
            outReport = self.prepareReport()

            # 
            self.writeToDS(outReport)

    # Goal: A simple wrapper that accounts for jitter, and provides values that can be mapped agnostically
    # ref: https://github.com/nondebug/dualsense
    # ref: https://github.com/nowrep/dualsensectl/blob/006f99b90f76ed27c89582a8d4997c420fffc366/main.c#l172
    # ref: https://github.com/nondebug/dualsense/blob/main/lsusb-descriptor-info.txt
    #      https://github.com/nondebug/dualsense/blob/8652ab7b8f4bd00f0f98636ca96b404d0a3afd9b/dualsense-explorer.html#L741
    def decrypt(self, msg):
        # this is for bluetooth only atm
        bytes = list(msg)
        c = {}
        ls = [bytes[2], bytes[3]]
        l1 = (bytes[10] & (1 << 0)) != 0        
        l2 = bytes[6]
        l2_button = (bytes[10] & (1 << 2)) != 0
        l3 = (bytes[10] & (1 << 7)) != 0

        c['left'] = { 'stick': ls, 'stick_down': l3, 'bumper': l1, 'trigger': l2, 'trigger_down': l2_button }
        
        rs = [bytes[4], bytes[5]]        
        r1 = (bytes[10] & (1 << 1)) != 0
        r2 = bytes[7]
        r2_button = (bytes[10] & (1 << 3)) != 0
        r3 = (bytes[10] & (1 << 6)) != 0
        c['right'] = { 'stick': rs, 'stick_down': r3, 'bumper': r1, 'trigger': r2, 'trigger_down': r2_button  }
        
        unknown_1 = bytes[8]
        triangle = (bytes[9] & (1 << 7)) != 0
        circle = (bytes[9] & (1 << 6)) != 0
        cross = (bytes[9] & (1 << 5)) != 0
        square = (bytes[9] & (1 << 4)) != 0
        dpad = { 0x8: '-', 0x0: 'n', 0x1: 'ne', 0x2:'e', 0x3:'se', 0x4:'s',0x5:'sw',0x6:'w',0x7:'nw' }    [(bytes[9] & 0xF)]
        c['buttons'] = { 'triangle': triangle, 'circle': circle, 'cross': cross, 'square': square }
        c['dpad'] = dpad
                
        button_options = (bytes[10] & (1 << 5)) != 0
        button_share = (bytes[10] & (1 << 5)) != 0
        button_ps = (bytes[11] & (1 << 0)) != 0
        button_touch = (bytes[11] & 0x02) != 0
        button_mic = (bytes[11] & 0x04) != 0
        c['config'] = { 'options': button_options, 'share': button_share, 'ps': button_ps, 'touch': button_touch, 'mic': button_mic }

        # this is right, right? not reversed?
        acc = [
            int.from_bytes(([msg[17], msg[18]]), byteorder='little', signed=True),
            int.from_bytes(([msg[19], msg[20]]), byteorder='little', signed=True),
            int.from_bytes(([msg[21], msg[22]]), byteorder='little', signed=True),
        ]
        c['accelerometer'] = acc
        gyro = [
            int.from_bytes(([msg[23], msg[24]]), byteorder='little', signed=True),
            int.from_bytes(([msg[25], msg[26]]), byteorder='little', signed=True),
            int.from_bytes(([msg[27], msg[28]]), byteorder='little', signed=True),
        ]
        c['gyroscope'] = gyro
        timestamp = int.from_bytes((msg[29], msg[30], msg[31], msg[32]), byteorder='little', signed=True)
        c['timestamp'] = timestamp
        # the touchpads are still wonky.. I dunno if it's a me/API thing, or the DS2 is just not great
        tp1 = {
            'id':  msg[34] & 0x7F,
            'active': (msg[34] & 0x80) == 0,
            'x': ((msg[36] & 0x0f) << 8) | (msg[35]),
            'y': ((msg[37]) << 4) | ((msg[36] & 0xf0) >> 4),
        }
        tp2 = {
            'id': msg[38] & 0x7F,
            'active': (msg[38] & 0x80) == 0,            
            'x': ((msg[40] & 0x0f) << 8) | (msg[39]),
            'y': ((msg[41]) << 4) | ((msg[40] & 0xf0) >> 4),
        }
        
        # for i in range(29,33):
        #     b = f"{bytes[i]:b}"
        #     b = f"{b.rjust(8, '0')}"
        #     print(f"byte[{i:>2}]\t{bytes[i]}\t{b}")
        #print(f'{tp1.id:<5} {tp1.active:<5} {tp1.x:<5} {tp1.y:<5}')
        #print(f'{tp2.id:<5} {tp2.active:<5} {tp2.x:<5} {tp2.y:<5}')        
        # print(f'{ax:<5} {ay:<5} {az:<5}')
        # print(f'{gx:<5} {gy:<5} {gz:<5}')
        # print('\n')        

        return c
        
    def readControllerBytes(self, inReport) -> None:
        """
        read the input from the controller and assign the states
        Args:
            inReport (bytearray): read bytearray containing the state of the whole controller
        """
        states=[]
        # utility to get acc/gyro values without cutting offf the first byte >_>
        msg=list(inReport)
        if self.connection_type == ConnectionType.BT:
            # the reports for BT and USB are structured the same,
            # but there is one more byte at the start of the bluetooth report.
            # We drop that byte, so that the format matches up again.
            states = list(inReport)[1:] # convert bytes to list
        else: # USB
            states = list(inReport) # convert bytes to list
            
        # self.states = states
        
        self.state.lj = [states[1]-127, states[2]-127]
        self.state.lj_pressed = (states[9] & (1 << 6)) != 0
        self.state.rj = [states[3]-127, states[4]-127]
        self.state.rj_pressed = (states[9] & (1 << 7)) != 0        
        self.state.l2 = states[5]
        self.state.r2 = states[6]

        # state 7 always increments -> not used anywhere

        buttonState = states[8]
        self.state.ps_triangle = (buttonState & (1 << 7)) != 0
        self.state.ps_circle = (buttonState & (1 << 6)) != 0
        self.state.ps_cross = (buttonState & (1 << 5)) != 0
        self.state.ps_square = (buttonState & (1 << 4)) != 0

        # dpad
        dpad_state = buttonState & 0x0F
        self.state.setDPadState(dpad_state)

        misc = states[9]
        # self.state.r3 = (misc & (1 << 7)) != 0
        # self.state.l3 = (misc & (1 << 6)) != 0
        self.state.btn_opts = (misc & (1 << 5)) != 0
        self.state.btn_share = (misc & (1 << 4)) != 0
        self.state.r2_pressed = (misc & (1 << 3)) != 0
        self.state.l2_pressed = (misc & (1 << 2)) != 0
        self.state.r1 = (misc & (1 << 1)) != 0
        self.state.l1 = (misc & (1 << 0)) != 0

        self.state.btn_ps = (states[10] & (1 << 0)) != 0
        self.state.btn_touchpad = (states[10] & 0x02) != 0
        self.state.btn_mic = (states[10] & 0x04) != 0

        # [todo] Look at the dualsense html explorer here, maybe need to normalize these values...?
        self.state.ltouchpad.id = inReport[33] & 0x7F
        self.state.ltouchpad.active = (inReport[33] & 0x80) == 0
        self.state.ltouchpad.xy = [
            ((inReport[35] & 0x0f) << 8) | (inReport[34]),
            ((inReport[36]) << 4) | ((inReport[35] & 0xf0) >> 4),
        ]
        self.state.rtouchpad.id = inReport[37] & 0x7F
        self.state.rtouchpad.active = (inReport[37] & 0x80) == 0
        self.state.rtouchpad.xy = [
            ((inReport[39] & 0x0f) << 8) | (inReport[38]),
            ((inReport[40]) << 4) | ((inReport[39] & 0xf0) >> 4),
        ]

        self.state.accelerom.set([
            int.from_bytes(([msg[17], msg[18]]), byteorder='little', signed=True),
            int.from_bytes(([msg[19], msg[20]]), byteorder='little', signed=True),
            int.from_bytes(([msg[21], msg[22]]), byteorder='little', signed=True),            
            # int.from_bytes(([inReport[16], inReport[17]]), byteorder='little', signed=True),
            # int.from_bytes(([inReport[18], inReport[19]]), byteorder='little', signed=True),
            # int.from_bytes(([inReport[20], inReport[21]]), byteorder='little', signed=True),
        ])        
        self.state.gyroscope.set([
            int.from_bytes(([msg[23], msg[24]]), byteorder='little', signed=True),
            int.from_bytes(([msg[25], msg[26]]), byteorder='little', signed=True),
            int.from_bytes(([msg[27], msg[28]]), byteorder='little', signed=True),            
            # int.from_bytes(([inReport[22], inReport[23]]), byteorder='little', signed=True),
            # int.from_bytes(([inReport[24], inReport[25]]), byteorder='little', signed=True),
            # int.from_bytes(([inReport[26], inReport[27]]), byteorder='little', signed=True),
        ])
        self.state.time = int.from_bytes((msg[29], msg[30], msg[31], msg[32]), byteorder='little', signed=True)
        # from kit-nya
        battery = states[53]
        self.battery.State = BatteryState((battery & 0xF0) >> 4)
        self.battery.Level = min((battery & 0x0F) * 10 + 5, 100)


    def writeToDS(self, outReport) -> None:
        self.device.write(bytes(outReport))

    def prepareReport(self) -> list:
        "Prepare the report to be sent to the controller"
        if self.connection_type == ConnectionType.USB:
            outReport = [0] * self.output_report_length # create empty list with range of output report
            # packet type
            outReport[0] = 0x02 # self.OUTPUT_REPORT_USB

            # flags determing what changes this packet will perform
            # 0x01 set the main motors (also requires flag 0x02); setting this by itself will allow rumble to gracefully terminate and then re-enable audio haptics, whereas not setting it will kill the rumble instantly and re-enable audio haptics.
            # 0x02 set the main motors (also requires flag 0x01; without bit 0x01 motors are allowed to time out without re-enabling audio haptics)
            # 0x04 set the right trigger motor
            # 0x08 set the left trigger motor
            # 0x10 modification of audio volume
            # 0x20 toggling of internal speaker while headset is connected
            # 0x40 modification of microphone volume
            outReport[1] = 0xff # [1]

            # further flags determining what changes this packet will perform
            # 0x01 toggling microphone LED
            # 0x02 toggling audio/mic mute
            # 0x04 toggling LED strips on the sides of the touchpad
            # 0x08 will actively turn all LEDs off? Convenience flag? (if so, third parties might not support it properly)
            # 0x10 toggling white player indicator LEDs below touchpad
            # 0x20 ???
            # 0x40 adjustment of overall motor/effect power (index 37 - read note on triggers)
            # 0x80 ???
            outReport[2] = 0x1 | 0x2 | 0x4 | 0x10 | 0x40 # [2]

            outReport[3] = self.rrumble # right low freq motor 0-255 # [3]
            outReport[4] = self.lrumble # left low freq motor 0-255 # [4]

            # outReport[5] - outReport[8] audio related

            # set Micrphone LED, setting doesnt effect microphone settings
            outReport[9] = self.audio.microphone_led # [9]

            outReport[10] = 0x10 if self.audio.microphone_mute is True else 0x00

            # add right trigger mode + parameters to packet
            outReport[11] = self.r2force.mode.value
            outReport[12] = self.r2force.forces[0]
            outReport[13] = self.r2force.forces[1]
            outReport[14] = self.r2force.forces[2]
            outReport[15] = self.r2force.forces[3]
            outReport[16] = self.r2force.forces[4]
            outReport[17] = self.r2force.forces[5]
            outReport[20] = self.r2force.forces[6]

            outReport[22] = self.l2force.mode.value
            outReport[23] = self.l2force.forces[0]
            outReport[24] = self.l2force.forces[1]
            outReport[25] = self.l2force.forces[2]
            outReport[26] = self.l2force.forces[3]
            outReport[27] = self.l2force.forces[4]
            outReport[28] = self.l2force.forces[5]
            outReport[31] = self.l2force.forces[6]

            outReport[39] = self.light.led_options
            outReport[42] = self.light.led_pulse_options
            outReport[43] = self.light.led_player_brightness
            outReport[44] = self.light.led_player_number
            outReport[45] = self.light.led_touchpad_color[0]
            outReport[46] = self.light.led_touchpad_color[1]
            outReport[47] = self.light.led_touchpad_color[2]

        elif self.connection_type == ConnectionType.BT:

            outReport = [0] * self.output_report_length # create empty list with range of output report
            # packet type
            outReport[0] = 0x31 # self.OUTPUT_REPORT_BT # bt type

            outReport[1] = 0x02

            # flags determing what changes this packet will perform
            # 0x01 set the main motors (also requires flag 0x02); setting this by itself will allow rumble to gracefully terminate and then re-enable audio haptics, whereas not setting it will kill the rumble instantly and re-enable audio haptics.
            # 0x02 set the main motors (also requires flag 0x01; without bit 0x01 motors are allowed to time out without re-enabling audio haptics)
            # 0x04 set the right trigger motor
            # 0x08 set the left trigger motor
            # 0x10 modification of audio volume
            # 0x20 toggling of internal speaker while headset is connected
            # 0x40 modification of microphone volume
            outReport[2] = 0xff # [1]

            # further flags determining what changes this packet will perform
            # 0x01 toggling microphone LED
            # 0x02 toggling audio/mic mute
            # 0x04 toggling LED strips on the sides of the touchpad
            # 0x08 will actively turn all LEDs off? Convenience flag? (if so, third parties might not support it properly)
            # 0x10 toggling white player indicator LEDs below touchpad
            # 0x20 ???
            # 0x40 adjustment of overall motor/effect power (index 37 - read note on triggers)
            # 0x80 ???
            outReport[3] = 0x1 | 0x2 | 0x4 | 0x10 | 0x40 # [2]

            outReport[4] = self.rrumble # right low freq motor 0-255 # [3]
            outReport[5] = self.lrumble # left low freq motor 0-255 # [4]

            # outReport[5] - outReport[8] audio related

            # set Micrphone LED, setting doesnt effect microphone settings
            outReport[10] = self.audio.microphone_led # [9]

            outReport[11] = 0x10 if self.audio.microphone_mute is True else 0x00

            # add right trigger mode + parameters to packet
            outReport[12] = self.r2force.mode.value
            outReport[13] = self.r2force.forces[0]
            outReport[14] = self.r2force.forces[1]
            outReport[15] = self.r2force.forces[2]
            outReport[16] = self.r2force.forces[3]
            outReport[17] = self.r2force.forces[4]
            outReport[18] = self.r2force.forces[5]
            outReport[21] = self.r2force.forces[6]

            outReport[23] = self.l2force.mode.value
            outReport[24] = self.l2force.forces[0]
            outReport[25] = self.l2force.forces[1]
            outReport[26] = self.l2force.forces[2]
            outReport[27] = self.l2force.forces[3]
            outReport[28] = self.l2force.forces[4]
            outReport[29] = self.l2force.forces[5]
            outReport[32] = self.l2force.forces[6]

            outReport[40] = self.light.led_options
            outReport[43] = self.light.led_pulse_options
            outReport[44] = self.light.led_player_brightness
            outReport[45] = self.light.led_player_number
            outReport[46] = self.light.led_touchpad_color[0]
            outReport[47] = self.light.led_touchpad_color[1]
            outReport[48] = self.light.led_touchpad_color[2]

            crcChecksum = compute(outReport)

            outReport[74] = (crcChecksum & 0x000000FF)
            outReport[75] = (crcChecksum & 0x0000FF00) >> 8
            outReport[76] = (crcChecksum & 0x00FF0000) >> 16
            outReport[77] = (crcChecksum & 0xFF000000) >> 24

        # if self.verbose:
        #     logger.debug(outReport)

        return outReport

class DSState:
    "All dualsense states (inputs) that can be read. Second method to check if a input is pressed." 
    def __init__(self) -> None:
        self.time = False
        self.accelerom = Vec3d()
        self.gyroscope = Vec3d()

        self.lj = [128, 128]
        self.lj_pressed = False # L3
        self.l1 = False
        self.l2 = False
        self.l2_pressed = False # L2Btn
        self.ltouchpad =  DSTouchpad()

        self.rj = [128, 128]
        self.rj_pressed = False # R3
        self.r1 = False
        self.r2 = False
        self.r2_pressed = False
        self.rtouchpad = DSTouchpad()
        
        self.dpad_up, self.dpad_down, self.dpad_left, self.dpad_right = False, False, False, False        
        self.ps_square, self.ps_triangle, self.ps_circle, self.ps_cross = False, False, False, False        
        self.btn_share, self.btn_opts, self.btn_ps,  self.btn_touchpad, self.btn_mic = False, False, False, False, False
        
    def __repr__(self):
        return "<{type} @{id:x} {attrs}>".format(
            type=self.__class__.__name__,
            id=id(self) & 0xFFFFFF,
            attrs=' '.join('{}: {!r}'.format(k, v) for k, v in self.__dict__.items()),
        )

    def __iter__(self):
        for key in self.__dict__:
            yield (key, getattr(self, key))

    def setDPadState(self, dpad_state: int):
        "Sets the dpad state variables according to the integers that was read from the controller"
        if dpad_state == 0x0:
            self.dpad_up = True
            self.dpad_down = False
            self.dpad_left = False
            self.dpad_right = False
        elif dpad_state == 0x1:
            self.dpad_up = True
            self.dpad_down = False
            self.dpad_left = False
            self.dpad_right = True
        elif dpad_state == 0x2:
            self.dpad_up = False
            self.dpad_down = False
            self.dpad_left = False
            self.dpad_right = True
        elif dpad_state == 0x3:
            self.dpad_up = False
            self.dpad_down = True
            self.dpad_left = False
            self.dpad_right = True
        elif dpad_state == 0x4:
            self.dpad_up = False
            self.dpad_down = True
            self.dpad_left = False
            self.dpad_right = False
        elif dpad_state == 0x5:
            self.dpad_up = False
            self.dpad_down = True
            self.dpad_left = False
            self.dpad_right = False
        elif dpad_state == 0x6:
            self.dpad_up = False
            self.dpad_down = False
            self.dpad_left = True
            self.dpad_right = False
        elif dpad_state == 0x7:
            self.dpad_up = True
            self.dpad_down = False
            self.dpad_left = True
            self.dpad_right = False
        else:
            # dpad not touched
            self.dpad_up = False
            self.dpad_down = False
            self.dpad_left = False
            self.dpad_right = False






# [todo] bring in thing for easing and stuff
class Vec3d:
    def __init__(self) -> None:
        self.pos = [0, 0, 0]
        # self.vel = [0, 0, 0]
        # self.acc = [0, 0, 0]
    def __repr__(self) -> str:
        return f"Vec3d({self.pos} vel={self.vel} acc={self.acc}"
    def __str__(self) -> str:
        return self.__repr__()
    def set(self, v):
        "Temporary utility :^)"
        self.pos = list(v)
        # self.vel = [0,0,0]
        # self.acc = [0,0,0]


# Rest is pydualsense classes
class DSTrigger:
    """Allows for multiple :class:`TriggerModes <pydualsense.enums.TriggerModes>` and multiple forces"""
    def __init__(self) -> None:
        self.forces = [0 for i in range(7)]        
        self.mode = TriggerModes.Off

    def setForce(self, forceID: int = 0, force: int = 0):
        """
            forceID (int, optional): defaults to 0, [0-6]
            force (int, optional): applied force to the parameter. Defaults to 0.
        """
        if not isinstance(forceID, int) or not isinstance(force, int):
            raise TypeError('forceID and force needs to be type int')
        if forceID > 6 or forceID < 0:
            raise Exception('only 7 parameters available')
        self.forces[forceID] = force

    def setMode(self, mode: TriggerModes):
        "Set the Mode for the Trigger"
        if not isinstance(mode, TriggerModes):
            raise TypeError('Trigger mode parameter needs to be of type `TriggerModes`')
        self.mode = mode


class DSTouchpad:
    "Dualsense Touchpad class. Contains X and Y position of touch and if the touch isActive"
    def __init__(self) -> None:
        self.id = 0        
        self.active = False
        self.xy = []
    def __repr__(self) -> str:
        return f"[{self.active}, {self.id}, {self.x}, {self.y}]"


# Rest aren't controls
class DSBattery:
    def __init__(self) -> None:
        self.battery_state = BatteryState.POWER_SUPPLY_STATUS_UNKNOWN
        self.batter_level = 0
    def __str__(self) -> str:
        return f"[state: {self.state}, level: {self.level}"
        
class DSAudio:
    def __init__(self) -> None:
        "initialize the limited Audio features of the controller"
        self.microphone_mute = 0
        self.microphone_led = 0

    def setMicrophoneLED(self, state: bool):
        "Activates or disables the microphone led. (This doesnt change the mute/unmutes the microphone itself)"
        if not isinstance(state, bool):
            raise TypeError('MicrophoneLED can only be a bool')
        self.microphone_led = value

    def setMicrophoneState(self, state: bool):
        "Set the microphone state and also sets the microphone led accordingle"
        if not isinstance(state, bool):
            raise TypeError('state needs to be bool')
        self.microphone_mute = state
        self.setMicrophoneLED(state)

class DSLight:
    "Represents all features of lights on the controller"
    def __init__(self) -> None:
        self.led_player_brightness = 0x2
        self.led_player_number = 0xef        
        self.led_options = 0x0
        self.led_pulse_options = 0x0
        self.led_touchpad_color = [0, 0, 255]

