this was in init:
            self.register_available_events()


def register_available_events(self) -> None:
        "register all available events that can be used for the controller"
        self.right_joystick_changed = Event()
        self.left_joystick_changed = Event()

        # button events
        self.ps_triangle_pressed = Event()
        self.ps_circle_pressed = Event()
        self.ps_cross_pressed = Event()
        self.ps_square_pressed = Event()

        # TODO: add a event that sends the pressed key if any key is pressedx
        # self.dpad_changed = Event()
        self.dpad_up = Event()
        self.dpad_down = Event()
        self.dpad_left = Event()
        self.dpad_right = Event()

        self.r1_changed = Event()
        self.r2_changed = Event()
        self.r3_changed = Event()
        self.l1_changed = Event()
        self.l2_changed = Event()
        self.l3_changed = Event()

        self.btn_ps_pressed = Event()
        self.touch_pressed = Event()
        self.btn_mic_pressed = Event()
        self.btn_share_pressed = Event()
        self.option_pressed = Event()
        self.gyro_changed = Event()
        self.accelerometer_changed = Event()    
        # touchpad touch ("handles 1 or 2 fingers")
        self.touchpad_frame_reported = Event()
        self.btn_touchpad_pressed = Event()



# then this was in readControllerBytes (or readReport)


        # TODO: control mouse with touchpad for fun as DS4Windows        
        # [tbd] okay does the event system do anything >_>
        if (EVENT_SYSTEM):
            # first call we dont have a "last state" so we create if with the first occurence
            if self.last_states is None:
                self.last_states = deepcopy(self.state)
                return
            if self.state.ps_circle != self.last_states.ps_circle:
                self.ps_circle_pressed(self.state.ps_circle)
            if self.state.ps_cross != self.last_states.ps_cross:
                self.ps_cross_pressed(self.state.ps_cross)
            if self.state.ps_triangle != self.last_states.ps_triangle:
                self.ps_triangle_pressed(self.state.ps_triangle)
            if self.state.ps_square != self.last_states.ps_square:
                self.ps_square_pressed(self.state.ps_square)
            
            if self.state.dpad_down != self.last_states.dpad_down:
                self.dpad_down(self.state.dpad_down)
            if self.state.dpad_left != self.last_states.dpad_left:
                self.dpad_left(self.state.dpad_left)
            if self.state.dpad_right != self.last_states.dpad_right:
                self.dpad_right(self.state.dpad_right)
            if self.state.dpad_up != self.last_states.dpad_up:
                self.dpad_up(self.state.dpad_up)
            
            if self.state.lx != self.last_states.lx or self.state.ly != self.last_states.ly:
                self.left_joystick_changed(self.state.lx, self.state.ly)
            if self.state.rx != self.last_states.rx or self.state.ry != self.last_states.ry:
                self.right_joystick_changed(self.state.rx, self.state.ry)
            if self.state.r1 != self.last_states.r1:
                self.r1_changed(self.state.r1)
            if self.state.r2 != self.last_states.r2:
                self.r2_changed(self.state.r2)
            if self.state.l1 != self.last_states.l1:
                self.l1_changed(self.state.l1)
            if self.state.l2 != self.last_states.l2:
                self.l2_changed(self.state.l2)
            if self.state.r3 != self.last_states.r3:
                self.r3_changed(self.state.r3)
            if self.state.l3 != self.last_states.l3:
                self.l3_changed(self.state.l3)
            if self.state.btn_ps != self.last_states.btn_ps:
                self.btn_ps_pressed(self.state.btn_ps)
            if self.state.btn_touchpad != self.last_states.btn_touchpad:
                self.btn_touchpad_pressed(self.state.btn_touchpad)
            if self.state.btn_mic != self.last_states.btn_mic:
                self.btn_mic_pressed(self.state.btn_mic)
            if self.state.btn_share != self.last_states.btn_share:
                self.btn_share_pressed(self.state.btn_share)
            if self.state.btn_opts != self.last_states.btn_opts:
                self.option_pressed(self.state.btn_opts)
            
            if self.state.accelerometer.x != self.last_states.accelerometer.x or self.state.accelerometer.y != self.last_states.accelerometer.y or \
                    self.state.accelerometer.z != self.last_states.accelerometer.z:
                self.accelerometer_changed(self.state.accelerometer.x, self.state.accelerometer.y, self.state.accelerometer.z)
            
            if self.state.gyro.pitch != self.last_states.gyro.pitch or self.state.gyro.yaw != self.last_states.gyro.yaw or \
                self.state.gyro.roll != self.last_states.gyro.roll:
                self.gyro_changed(self.state.gyro.pitch, self.state.gyro.yaw, self.state.gyro.roll)

            self.last_states = deepcopy(self.state)
        
