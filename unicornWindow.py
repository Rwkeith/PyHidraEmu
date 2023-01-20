import dearpygui.dearpygui as dpg
import threading
import sys
import dearpygui.demo as demo
from unicornEmu import *


class UnicornWindow():
    def __init__(self, unicorn_cpu, unicorn_memory_map):
        self.unicorn_cpu = unicorn_cpu
        self.unicorn_memory_map = unicorn_memory_map
        t1 = threading.Thread(target=self.unicorn_window)
        t1.start()

    def update_context(self, sender, app_data, user_data):
        print(f'Updating {user_data} to {app_data}')
        self.unicorn_cpu.set_register(user_data, app_data)
        threads = threading.enumerate()
        for thread in threads:
            print(f"Thread {thread.name} is alive?: {thread.is_alive()}")

    def unicorn_window(self):
        # try:
        reg_dict = {}
        for value in range(0, 31):
            reg_dict[f'x{value}'] = True

        dpg.create_context()
        # with dpg.theme() as input_text_transparent_theme:
        #     with dpg.theme_component(dpg.mvInputText):
        #         dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (0, 0, 0, 0))

        with dpg.window(label="Register Window", no_move=True, no_resize=True, no_title_bar=True):
            with dpg.table(header_row=True, row_background=True, tag="registerWin",
                           policy=dpg.mvTable_SizingFixedSame,
                           width=200):
                # dpg.configure_item("registerWin", )
                # use add_table_column to add columns to the table,
                # table columns use child slot 0
                dpg.add_table_column(label='Register', width_fixed=True, width=50)
                dpg.add_table_column(label='Value', width_fixed=True, width=50)

                for i in range(0, 31):
                    with dpg.table_row():
                        register = f'x{i}'
                        dpg.add_text(register)
                        dpg.add_input_text(default_value=0, callback=self.update_context, user_data=register,
                                           on_enter=True)
                        # dpg.set_value(text_item, value=self.unicorn_cpu.context[f'x{i}'])
                        # dpg.bind_item_theme(dpg.last_item(), input_text_transparent_theme)

        dpg.create_viewport(title='Unicorn Console', width=800, height=600)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()
        # except:
        #     exc_type, exc_value, exc_traceback = sys.exc_info()
        #     print("An exception of type", exc_type, "occurred with the following message:", exc_value)


# def do_demo():
#     dpg.create_context()
#     dpg.create_viewport(title='Custom Title', width=600, height=600)
#
#     demo.show_demo()
#
#     dpg.setup_dearpygui()
#     dpg.show_viewport()
#     dpg.start_dearpygui()
#     dpg.destroy_context()


# if __name__ == '__main__':
#     t1 = threading.Thread(target=unicorn_window)
#     t1.start()
#     t1.join()