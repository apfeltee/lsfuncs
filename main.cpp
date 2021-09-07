
/*
* todo:
* + don't use imgapi, but instead use PE parser ... which would make lsfuncs far more portable,
*   not to mention usable with .net binaries
*
* + check for various flavours of function mangling, and demangle accordingly (i.e., gnu, etc)
*/


#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <exception>
#include <stdexcept>
#include <cstdlib>
#include "optionparser.hpp"

#if defined(__GNUC)
	#define COMP_ISGCC
#elif defined(_MSC_VER)
	#define COMP_ISMSCV
#endif

/* --- */
// windows specific headers
#include <windows.h>
#include <shlwapi.h>
#include <imagehlp.h>
//#include <dbghelp.h>


#if defined(COMP_ISGCC)
	// gcc specific headers
	#include <cxxabi.h>
#endif


namespace Utils
{
    static std::string quot(const std::string& str)
    {
        std::stringstream buf;
        buf << '"';
        for(auto ch: str)
        {
            if(ch == '"')
            {
                buf << "\\\"";
            }
            else
            {
                buf << char(ch);
            }
        }
        buf << '"';
        return buf.str();
    }

    static DWORD lastError()
    {
        return ::GetLastError();
    }

    static std::string lastErrorMessage(DWORD errid)
    {
        LPSTR buffer;
        size_t size;
        std::string msg;
        buffer = nullptr;
        if(errid == 0)
        {
            return "No Error / Unknown";
        }
        size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errid,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&buffer,
            0,
            NULL
        );
        msg.append(buffer, size);
        LocalFree(buffer);
        return msg;
    }

    static std::string demangle_msvc(const std::string& str)
    {
        size_t sz;
        size_t bufsz;
        char* buffer;
        std::string rtname;
        bufsz = str.size() + 128;
        buffer = new char[bufsz];
        if((sz = UnDecorateSymbolName(str.c_str(), buffer, bufsz, UNDNAME_COMPLETE)) > 0)
        {
            rtname.append(buffer, sz);
        }
        else
        {
            rtname.append(str);
        }
        delete[] buffer;
        return rtname;
    }

	#if defined(COMP_ISGCC)
    static std::string demangle_gcc(const std::string& str)
    {
        int status;
        size_t len;
        char* realname;
        std::string ret;
        if((realname = abi::__cxa_demangle(str.c_str(), 0, &len, &status)) == NULL)
        {
            return str;
        }
        ret.append(realname, len);
        free(realname);
        return ret;
    }
	#endif

    static std::string demangle_guess(const std::string& str, bool* isdem)
    {
        std::string ret;
        if(str[0] == '?')
        {
            if((ret = demangle_msvc(str)) != str)
            {
                *isdem = true;
                return ret;
            }
        }
		#if defined(COMP_ISGCC)
        else if((str[0] == '_') && (str[1] == 'Z'))
        {
            if((ret = demangle_gcc(str)) != str)
            {
                *isdem = true;
                return ret;
            }
        }
		#endif
        return str;
    }

    static std::string fixcygpath(const std::string& path)
    {
        std::string npath;
        // turn cygdrive paths into windows paths
        // windows supports forward slashes just fine
        if(path.substr(0, 9) == "/cygdrive")
        {
            // append drive letter
            npath.push_back(path[10]);
            npath.push_back(':');
            // append the rest of the path
            npath.append(path.substr(11));
            return npath;
        }
        else if(path[0] == '/')
        {
            npath.append("C:/cygwin");
            npath.append(path);
            return npath;
        }
        return path;
    }

    std::string makebasename(const std::string& path)
    {
        size_t ofs;
        ofs = path.find_last_of("/\\");
        if(ofs == std::string::npos)
        {
            return path;
        }
        return path.substr(ofs + 1);
    }
}

class ImageExports
{
    public: // types
        enum ImageType
        {
            ITYP_UNKNOWN = 0,
            ITYP_NATIVEPEDLL = 1,
            ITYP_DOTNETDLL = 2,
        };

        struct ExportedFunc
        {
            std::string rawname;
            std::string demangled;
            bool isdemangled;
            DWORD address;
        };

        using ExportsList = std::vector<ExportedFunc>;

        // exceptions
        class BaseError: public std::runtime_error
        {
            private:
                std::string m_errstr;
                DWORD m_errcode;

            public:
                BaseError(const std::string& msg, const std::string& errstr, DWORD errcode):
                    std::runtime_error(msg),
                    m_errstr(errstr),
                    m_errcode(errcode)
                {}

                DWORD errCode() const
                {
                    return m_errcode;
                }

                std::string errMessage() const
                {
                    return m_errstr;
                }
        };

        struct FileReadError: BaseError
        {
            FileReadError(const std::string& m, const std::string& e, DWORD c):
                BaseError(m, e, c)
            {}
        };

        struct InvalidImageError: BaseError
        {
            InvalidImageError(const std::string& m, const std::string& e, DWORD c):
                BaseError(m, e, c)
            {}
        };

        struct BadImageError: BaseError
        {
            BadImageError(const std::string& m, const std::string& e, DWORD c):
                BaseError(m, e, c)
            {}
        };

    private: // vars
        std::string m_path;
        ExportsList m_exports = {};

    private: // functions
        template<typename Exception>
        static void error(const std::string& msg)
        {
            DWORD errcode;
            std::string errstr;
            errcode = Utils::lastError();
            errstr = Utils::lastErrorMessage(errcode);
            throw Exception(msg, errstr, errcode);
        }

        void loadPEFile()
        {
            size_t i;
            bool isdemangled;
            //void* saddr;
            const void* rawname;
            const char* rawstr;
            std::string funcname;
            DWORD* vanames;
            PIMAGE_SECTION_HEADER sechdr;
            PIMAGE_EXPORT_DIRECTORY imgdir;
            ULONG dirsize;
            LOADED_IMAGE peimg;
            vanames = nullptr;
            sechdr = nullptr;
            if(MapAndLoad(m_path.c_str(), NULL, &peimg, TRUE, TRUE))
            {
                // this'll fail for some PE files... not entirely clear why,
                // as not even GetLastError provides much information :-/
                // also, according to msdn, ImageDirectoryEntryToData has
                // been superseded by ImageDirectoryEntryToDataEx ... ?
                /*
                    typedef struct _IMAGE_EXPORT_DIRECTORY
                    {
                        DWORD Characteristics;
                        DWORD TimeDateStamp;
                        WORD MajorVersion;
                        WORD MinorVersion;
                        DWORD Name;
                        DWORD Base;
                        DWORD NumberOfFunctions;
                        DWORD NumberOfNames;
                        DWORD AddressOfFunctions;
                        DWORD AddressOfNames;
                        DWORD AddressOfNameOrdinals;
                    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

                    typedef struct _IMAGE_SECTION_HEADER
                    {
                        BYTE Name[8];
                        union {
                            DWORD PhysicalAddress;
                            DWORD VirtualSize;
                        } Misc;
                        DWORD VirtualAddress;
                        DWORD SizeOfRawData;
                        DWORD PointerToRawData;
                        DWORD PointerToRelocations;
                        DWORD PointerToLinenumbers;
                        WORD NumberOfRelocations;
                        WORD NumberOfLinenumbers;
                        DWORD Characteristics;
                    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
                */
                imgdir = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
                    peimg.MappedAddress,
                    false,
                    IMAGE_DIRECTORY_ENTRY_EXPORT,
                    &dirsize
                );
                if(imgdir != NULL)
                {
                    vanames = (DWORD *)ImageRvaToVa(
                        peimg.FileHeader, 
                        peimg.MappedAddress,
                        imgdir->AddressOfNames,
                        NULL
                    );
                    for(i=0; i<(imgdir->NumberOfNames); i++)
                    {
                        rawname = (const void*)ImageRvaToVa(
                            peimg.FileHeader, 
                            peimg.MappedAddress,
                            vanames[i],
                            &sechdr
                        );
                        if(sechdr != nullptr)
                        {
                            /*
                            fprintf(stderr, "sechdr for '%s' isn't NULL:\n", rawname);
                            #define _pv(v) \
                                fprintf(stderr, "  %s: 0x%X (%d)\n", #v, v, v);
                            _pv(peimg.MappedAddress);
                            _pv(vanames[i]);
                            _pv(sechdr->VirtualAddress);
                            _pv(sechdr->Misc.PhysicalAddress);
                            #undef _pv
                            fprintf(stderr, "\n");
                            */
                        }
                        isdemangled = false;
                        rawstr = (const char*)rawname;
                        funcname = Utils::demangle_guess(std::string(rawstr), &isdemangled);
                        //saddr = (peimg.MappedAddress + i);
                        m_exports.push_back(ExportedFunc{
                            rawstr,
                            funcname,
                            isdemangled,
                            vanames[i]
                        });
                        
                    }
                }
                else
                {
                    error<BadImageError>("cannot read virtual addresses");
                }
                UnMapAndLoad(&peimg);
            }
            else
            {
                error<InvalidImageError>("cannot map file");
            }
        }

        ImageType guessImageType()
        {
            size_t rt;
            FILE* fh;
            char buffer[80 + 1];
            if((fh = fopen(m_path.c_str(), "rb")) == NULL)
            {
                error<FileReadError>("file cannot be read");
            }
            rt = fread(buffer, sizeof(char), 80, fh);
            fclose(fh);
            // relevant header starts at 60 bytes
            if(rt < 65)
            {
                error<InvalidImageError>("invalid image or header truncated");
            }
            else
            {
                if((buffer[0] == 'M') && (buffer[1] == 'Z'))
                {
                    return ITYP_NATIVEPEDLL;
                }
                // other checks ...
                else
                {
                    error<InvalidImageError>("not a PE dll");
                }
            }
            // never actually reached
            return ITYP_UNKNOWN;
        }

        void loadFile()
        {
            ImageType ityp;
            ityp = guessImageType();
            switch(ityp)
            {
                case ITYP_NATIVEPEDLL:
                    return loadPEFile();
                default:
                    // nothing, already handled by guessImageType()
                    break;
            }
        }

    public:
        ImageExports(const std::string& path): m_path(path)
        {
            loadFile();
        }

        ExportsList exports()
        {
            return m_exports;
        }
};

/* -- end of guts -- */

namespace App
{
    enum class TextTypes
    {
        OutPlaintext  = 0,
        OutJSON       = 1,
        OutRawSyms    = 2,
        /* more to come, maybe? idk */
    };


    struct Options
    {
        bool want_demangled = false;
        TextTypes otype = TextTypes::OutPlaintext;
        std::string custfieldsep;
        std::fstream* filehnd = nullptr;
        std::ostream* fout = &std::cout;
        bool haveoutfile = false;
        bool basenameify = false;
    };

    namespace Output
    {
        class BaseOutput
        {
            protected:
                Options& options;
                std::string filename;
                std::string dispname;
                ImageExports::ExportsList& exports;

            public:
                BaseOutput(Options& opts, const std::string& fn, const std::string dispfn, ImageExports::ExportsList& ex):
                    options(opts), filename(fn), dispname(dispfn), exports(ex)
                {
                }

                virtual ~BaseOutput()
                {
                }

                size_t size() const
                {
                    return exports.size();
                }

                std::string getSymbolName(ImageExports::ExportedFunc& exfn) const
                {
                    if(exfn.isdemangled && options.want_demangled)
                    {
                        return exfn.demangled;
                    }
                    return exfn.rawname;
                }

                virtual void writeBegin(std::ostream& out) = 0;
                virtual void writeItem(std::ostream& out, size_t i, bool isend) = 0;
                virtual void writeEnd(std::ostream& out) = 0;

                void write(std::ostream& out)
                {
                    size_t i;
                    writeBegin(out);
                    for(i=0; i<size(); i++)
                    {
                        writeItem(out, i, (i + 1) == size());
                    }
                    writeEnd(out);
                }
        };

        struct AsPlainText: BaseOutput
        {
            using BaseOutput::BaseOutput;
            std::string fieldsep = " ";

            void writeBegin(std::ostream&)
            {
            }

            void writeItem(std::ostream& out, size_t i, bool)
            {
                auto exfn = exports[i];
                /*
                    <filename> <index> <ofs> <symbol>
                */
                out
                    << dispname << fieldsep
                    << std::dec << std::setw(5) << std::setfill('0') << i << fieldsep
                    << "0x" << std::hex << exfn.address << fieldsep
                    << getSymbolName(exfn);
                ;
                out << std::endl;
            }

            void writeEnd(std::ostream&)
            {
            }
        };

        struct AsRawSymbols: BaseOutput
        {
            using BaseOutput::BaseOutput;

            void writeBegin(std::ostream&)
            {
            }

            void writeEnd(std::ostream&)
            {
            }

            void writeItem(std::ostream& out, size_t i, bool)
            {
                out << exports[i].rawname << std::endl;
            }
        };

        struct AsJSON: BaseOutput
        {
            using BaseOutput::BaseOutput;

            void writeBegin(std::ostream& out)
            {
                out << "{\"file\": " << Utils::quot(filename) << ", \"symbols\": [" << std::endl;
            }

            void writeItem(std::ostream& out, size_t i, bool isend)
            {
                auto exfn = exports[i];
                out << "    ";
                out << "{" << "\"name\": " << Utils::quot(exfn.rawname);
                if(exfn.isdemangled)
                {
                    out << ", \"demangled\": " << Utils::quot(exfn.demangled);
                }
                out << "}";
                if(!isend)
                {
                    out << ",";
                }
                out << std::endl;
            }

            void writeEnd(std::ostream& out)
            {
                out << "]}" << std::endl;
            }
        };
    };

    class LsFuncsProgram
    {

        private:
            Options options;
            int errcount;
            std::string fpath;
            std::string dispath;
            Output::BaseOutput* outputter;
            ImageExports::ExportsList explist;
            std::vector<std::string> args;
            OptionParser prs;

        public:
            LsFuncsProgram()
            {
                errcount = 0;
                setupflags(prs);
            }

            void setupflags(OptionParser& prs)
            {
                prs.on({"-t", "--text"}, "output line-based representation (default)", [&]
                {
                    options.otype = TextTypes::OutPlaintext;
                });
                prs.on({"-j", "--json"}, "output as json", [&]
                {
                    options.otype = TextTypes::OutJSON;
                });
                prs.on({"-b", "--basename"}, "turn full paths into basenames ('c:/.../foo.dll' -> 'foo.dll')", [&]
                {
                    options.basenameify = true;
                });
                prs.on({"-r", "--raw"}, "output raw symbol names", [&]
                {
                    options.otype = TextTypes::OutRawSyms;
                });
                prs.on({"-d", "--demangled"}, "print demangled symbol instead of raw (only applies to '--text')", [&]
                {
                    options.want_demangled = true;
                });
                prs.on({"-s?", "--separator=?"}, "set separator for '--text' (ignored for other output modes)", [&](const OptionParser::Value& v)
                {
                    options.custfieldsep = v.str();
                });
                prs.on({"-o?", "--output=?"}, "write output to file", [&](const OptionParser::Value& v)
                {
                    auto filepath = v.str();
                    options.filehnd = new std::fstream(filepath, std::ios::out | std::ios::binary);
                    if(options.filehnd->good() == false)
                    {
                        delete options.filehnd;
                        std::cerr << "cannot open '" << filepath << "' for writing" << std::endl;
                        std::exit(1);
                    }
                    options.haveoutfile = true;
                    options.fout = options.filehnd;
                    
                });
                prs.on({"-h", "--help"}, "show help", [&]
                {
                    prs.help(std::cout);
                    return 0;
                });
            }

            bool parse_options(int argc, char** argv)
            {
                try
                {
                    return prs.parse(argc, argv);
                }
                catch(std::runtime_error& err)
                {
                    std::cerr << "failed to parse options: " << err.what() << std::endl;
                }
                return false;
            }

            int main(int argc, char** argv)
            {
                if(argc > 1)
                {
                    if(!parse_options(argc, argv))
                    {
                        return 0;
                    }
                    args = prs.positional();
                    for(auto& sarg: args)
                    {
                        fpath = Utils::fixcygpath(sarg);
                        dispath = options.basenameify ? Utils::makebasename(fpath) : fpath;
                        try
                        {
                            ImageExports img(fpath);
                            explist = img.exports();
                            switch(options.otype)
                            {
                                case TextTypes::OutJSON:
                                    outputter = new Output::AsJSON(options, fpath, dispath, explist);
                                    break;
                                case TextTypes::OutPlaintext:
                                    outputter = new Output::AsPlainText(options, fpath, dispath, explist);
                                    break;
                                case TextTypes::OutRawSyms:
                                    outputter = new Output::AsRawSymbols(options, fpath, dispath, explist);
                                    break;
                                default:
                                    outputter = new Output::AsPlainText(options, fpath, dispath, explist);
                                    options.otype = TextTypes::OutPlaintext;
                                    break;
                            }
                            if(options.otype == TextTypes::OutPlaintext)
                            {
                                if(!options.custfieldsep.empty())
                                {
                                    ((Output::AsPlainText*)outputter)->fieldsep = options.custfieldsep;
                                }
                            }
                            outputter->write(*options.fout);
                            delete outputter;
                        }
                        catch(ImageExports::BaseError& err)
                        {
                            errcount += 1;
                            std::cerr << "exception: " << sarg << ": " << err.what();
                            if(err.errCode() > 0)
                            {
                                std::cerr << " (" << err.errCode() << ", " << err.errMessage() << ")";
                            }
                            std::cerr << std::endl;
                            if(args.size() == 1)
                            {
                                return 1;
                            }
                            // otherwise, keep going
                        }
                    }
                    return (errcount > 0);
                }
                else
                {
                    std::cerr << "missing an argument! try '" << argv[0] << "' --help" << std::endl;
                    return 1;
                }
                if(options.haveoutfile)
                {
                    delete options.filehnd;
                }
                return 0;
            }
    };
}

int main(int argc, char* argv[])
{
    App::LsFuncsProgram lsfp;
    return lsfp.main(argc, argv);
}

