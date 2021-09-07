
#include <stdio.h>
#include <windows.h>
#include <winnt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>



typedef struct
{
    unsigned char Name[8];
    unsigned int VirtualSize;
    unsigned int VirtualAddress;
    unsigned int SizeOfRawData;
    unsigned int PointerToRawData;
    unsigned int PointerToRelocations;
    unsigned int PointerToLineNumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLineNumbers;
    unsigned int Characteristics;
} sectionHeader;

sectionHeader *sections;
unsigned int NumberOfSections = 0;

int Rva2Offset(unsigned int rva)
{
    int i = 0;

    for(i = 0; i < NumberOfSections; i++)
    {
        unsigned int x = sections[i].VirtualAddress + sections[i].SizeOfRawData;

        if(x >= rva)
        {
            return sections[i].PointerToRawData + (rva + sections[i].SizeOfRawData) - x;
        }
    }

    return -1;
}

void EnumExportedFunctions(const char *szFilename, void (*callback)(const char*, const char*, void*), void* userptr)
{
    int i;
    int offset;
    int szNameLen;
    char c;
    unsigned int y;
    unsigned int pos;
    unsigned int namesOffset;
    unsigned int e_lfanew;
    unsigned int NumberOfRvaAndSizes;
    unsigned int ExportVirtualAddress;
    unsigned int ExportSize;
    unsigned int NumberOfNames;
    unsigned int AddressOfNames;
    char* szName;
    FILE* hFile;
    i = 0;
    y = 0;
    e_lfanew = 0;
    NumberOfRvaAndSizes = 0;
    ExportVirtualAddress = 0;
    ExportSize = 0;
    NumberOfNames = 0;
    AddressOfNames = 0;
    hFile = fopen(szFilename, "rb");
    if(hFile != NULL)
    {
        if((fgetc(hFile) == 'M') && (fgetc(hFile) == 'Z'))
        {
            fseek(hFile, 0x3C, SEEK_SET);
            fread(&e_lfanew, 4, 1, hFile);
            fseek(hFile, e_lfanew + 6, SEEK_SET);
            fread(&NumberOfSections, 2, 1, hFile);
            fseek(hFile, 108, SEEK_CUR);
            fread(&NumberOfRvaAndSizes, 4, 1, hFile);
            if(NumberOfRvaAndSizes == 16)
            {
                fread(&ExportVirtualAddress, 4, 1, hFile);
                fread(&ExportSize, 4, 1, hFile);
                if(ExportVirtualAddress > 0 && ExportSize > 0)
                {
                    fseek(hFile, 120, SEEK_CUR);
                    if(NumberOfSections > 0)
                    {
                        sections = (sectionHeader *)malloc(
                        NumberOfSections * sizeof(sectionHeader));
                        for(i = 0; i < NumberOfSections; i++)
                        {
                            fread(sections[i].Name, 8, 1, hFile);
                            fread(&sections[i].VirtualSize, 4, 1, hFile);
                            fread(&sections[i].VirtualAddress, 4, 1, hFile);
                            fread(&sections[i].SizeOfRawData, 4, 1, hFile);
                            fread(&sections[i].PointerToRawData, 4, 1, hFile);
                            fread(&sections[i].PointerToRelocations, 4, 1, hFile);
                            fread(&sections[i].PointerToLineNumbers, 4, 1, hFile);
                            fread(&sections[i].NumberOfRelocations, 2, 1, hFile);
                            fread(&sections[i].NumberOfLineNumbers, 2, 1, hFile);
                            fread(&sections[i].Characteristics, 4, 1, hFile);
                        }
                        offset = Rva2Offset(ExportVirtualAddress);
                        fseek(hFile, offset + 24, SEEK_SET);
                        fread(&NumberOfNames, 4, 1, hFile);
                        fseek(hFile, 4, SEEK_CUR);
                        fread(&AddressOfNames, 4, 1, hFile);
                        namesOffset = Rva2Offset(AddressOfNames);
                        fseek(hFile, namesOffset, SEEK_SET);
                        for(i = 0; i < NumberOfNames; i++)
                        {
                            fread(&y, 4, 1, hFile);
                            pos = ftell(hFile);
                            fseek(hFile, Rva2Offset(y), SEEK_SET);
                            c = fgetc(hFile);
                            szNameLen = 0;
                            while(c != '\0')
                            {
                                c = fgetc(hFile);
                                szNameLen++;
                            }
                            fseek(hFile, (-szNameLen) - 1, SEEK_CUR);
                            szName = (char*)calloc(szNameLen + 1, 1);
                            fread(szName, szNameLen, 1, hFile);
                            callback(szFilename, szName, userptr);
                            free(szName);
                            fseek(hFile, pos, SEEK_SET);
                        }
                    }
                }
            }
        }
        fclose(hFile);
    }
}

void mycallback(const char* dllname, const char *fname, void *ptr)
{
    printf("%s %s\n", dllname, fname);
}

void listfuncs(const char *dllfile)
{
    EnumExportedFunctions(dllfile, mycallback, NULL);
}

int main(int argc, char *argv[])
{
    int i;
    for(i = 1; i < argc; i++)
    {
        listfuncs(argv[i]);
    }
}
