from ast import While
import subprocess
from platform import release
import shutil
import time
import os
from os.path import exists


def toBinaryAux(clause):
    if '-' in clause:
        return 1
    else:
        return 0


def toBinary(list):
    tot = " "

    for i in list:
        tot = tot + str(toBinaryAux(i))

    return tot


totalStart = time.time()

for cont in range(0, 1000):

    Nsol = 0

    # Timer variable
    start = time.time()

    # File input variable
    fileIn = "/mnt/hgfs/Tesi/Test/TestTesiNuovi/120/" + str(cont) + "output.cnf"
    if not exists(fileIn):
        break

    # File in which clause will be added
    fileBak = "/mnt/hgfs/Tesi/Test/TestTesiNuovi/120/" + str(cont) + "output" + "2" + ".cnf"

    print("Create copy of the cnf file...")
    shutil.copyfile(fileIn, fileBak)
    file_object = open(fileBak, 'a', newline='\n')

    # File in which time are printed
    solutionFile = open(
        '/mnt/hgfs/Tesi/Test/TestTesiNuovi/120/' + str(cont) + 'solution2.txt',
        'w',
        newline='\n'
    )

    print("Start working on file " + str(cont))

    while True:
        ############################################################ KISSAT
        result = subprocess.run(
            [
                '/mnt/hgfs/Tesi/Test/Ubuntu/kissat-master/build/kissat',
                fileBak,
                "--relaxed",
                "-q"
            ],
            stdout=subprocess.PIPE
        ).stdout.decode('utf-8')
        ############################################################

        try:
            index = result.index("v")
        except Exception:
            break

        Nsol = Nsol + 1
        print(
            "Solution N" + str(Nsol) + " found..."
            + " {" + str(time.time() - start) + "}"
        )

        # ADD NEW CLAUSE TO CNF
        result = result[result.index("v"):result.index("1728") + 4]
        result = result.strip()
        result = result.replace("v ", "")
        result = result.replace("\n", "")
        result = result.replace("\r", "")
        result = result.replace(" -", " +")
        result = result.replace(" ", " -")
        result = result.replace("+", " ")

        # WRITING SOLUTION TO FILE
        file_object.write(result[1:] + " 0\n")

        try:
            solution = result[:result.index("-129 ")]
        except Exception:
            solution = result[:result.index(" 129 ")]

        solutionFile.write(
            "SOLUTION N" + str(Nsol)
            + " [" + str(time.time() - start) + "]\n"
        )
        solution = solution.strip()

        # BINARY
        tot = toBinary(solution.split())
        solutionFile.write(tot + "\n")
        print(tot)

        # HEX
        decimal_representation = int(tot, 2)
        hexer = hex(decimal_representation)
        hexer = hexer[2:]

        for j in range(len(hexer), 32):
            hexer = "0" + hexer

        solutionFile.write(hexer + "\n")
        print(hexer)

        # ASCI STRING
        bytes_object = bytes.fromhex(hexer)
        ascii_string = bytes_object.decode('utf-8', 'ignore')
        solutionFile.write(ascii_string + "\n\n")
        print(ascii_string + "\n")

    end = time.time()
    appo = end - start

    print(
        "\nTime for computing solution on file " + str(cont)
        + " : " + str(appo) + " s\n"
    )

    solutionFile.write("Total time : " + str(appo) + " s\n")

    file_object.close()
    solutionFile.close()

    os.remove(fileBak)


totalEnd = time.time()
final = totalEnd - totalStart

print("Total time : " + str(final))
print("Done!")
