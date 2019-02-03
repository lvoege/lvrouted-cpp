dit is een rechtoe-rechtaan port van lvrouted naar c++:

  - namen van files en functies zijn ongeveer hetzelfde. Foo.ml is hier
    Foo.hpp en Foo.cpp.
  - de inhoud van files wat betreft wat er in zit en functionaliteit is
    ongeveer hetzelfde. dat beter maken, en er valt nogal wat te verbeteren,
    komt later.
  - de laagste-niveau C routines zijn hier meestal inline in de aanroepende
    functies gezet. min de lijm die nodig was voor ocaml en dan eventueel met
    wat kleine aanpassingen als dat het geheel ineens veel beter op elkaar
    laat passen.
  - malloc() en free() zijn wel vervangen door std::unique_ptr<>s of stack
    arrays
  - resources zoals file handles zitten hier in een RAII wrapper
  - er zijn een paar dingen nog niet geport, zoals het gebruik van een config
    file en het her-lezen van de configuratie (en config file) met een SIGHUP.

er is een CMakeLists.txt voor IDEs, en ook een gewone Makefile waarmee die een
FreeBSD 11.2 zonder verdere software kan compilen naar een binary.

het compiled ook onder Linux maar doet dan weinig. ik heb dat gebruikt om wat
te debuggen met valgrind, want ik kreeg valgrind onder FreeBSD niet aan de
praat en asan ook niet.
