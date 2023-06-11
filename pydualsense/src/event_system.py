from collections import defaultdict


class Event(object):
    """
    Base class for the event driven system
    """

    def __init__(self) -> None:
        """
        initialise event system
        """
        self._event_handler = []

    def subscribe(self, fn):
        """
        add a event subscription

        Args:
            fn (function): _description_
        """
        self._event_handler.append(fn)
        print('Subscirbee??????????')        
        return self

    def unsubscribe(self, fn):
        """
        delete event subscription fn

        Args:
            fn (function): _description_
        """
        self._event_handler.remove(fn)
        print('unsubirlbirenb??')
        return self

    def __iadd__(self, fn):
        """
        add event subscription fn

        Args:
            fn (function): _description_
        """
        self._event_handler.append(fn)
        print('isadd??????????')        
        return self

    def __isub__(self, fn):
        """
        delete event subscription fn

        Args:
            fn (function): _description_
        """
        self._event_handler.remove(fn)
        print('isbu??????????')
        return self

    def __call__(self, *args, **keywargs):
        """
        calls all event subscription functions
        """
        for eventhandler in self._event_handler:
            print('serisousely wat')
            eventhandler(*args, **keywargs)
