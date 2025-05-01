EXECUTABLE = bchoc

MAIN_SCRIPT = bchoc.py

SOURCES = bchoc.py Block.py

all:$(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	cp $(MAIN_SCRIPT) $(EXECUTABLE)
	chmod +x $(EXECUTABLE)

clean:
	@echo "Cleaning up..."
	rm -f $(EXECUTABLE)

.PHONY: all clean
