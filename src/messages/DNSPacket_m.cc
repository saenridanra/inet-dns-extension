//
// Generated file, do not edit! Created by nedtool 4.6 from src/applications/../utils/../messages/DNSPacket.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#  pragma warning(disable:4101)
#  pragma warning(disable:4065)
#endif

#include <iostream>
#include <sstream>
#include "DNSPacket_m.h"

USING_NAMESPACE


// Another default rule (prevents compiler from choosing base class' doPacking())
template<typename T>
void doPacking(cCommBuffer *, T& t) {
    throw cRuntimeError("Parsim error: no doPacking() function for type %s or its base class (check .msg and _m.cc/h files!)",opp_typename(typeid(t)));
}

template<typename T>
void doUnpacking(cCommBuffer *, T& t) {
    throw cRuntimeError("Parsim error: no doUnpacking() function for type %s or its base class (check .msg and _m.cc/h files!)",opp_typename(typeid(t)));
}




// Template rule for outputting std::vector<T> types
template<typename T, typename A>
inline std::ostream& operator<<(std::ostream& out, const std::vector<T,A>& vec)
{
    out.put('{');
    for(typename std::vector<T,A>::const_iterator it = vec.begin(); it != vec.end(); ++it)
    {
        if (it != vec.begin()) {
            out.put(','); out.put(' ');
        }
        out << *it;
    }
    out.put('}');
    
    char buf[32];
    sprintf(buf, " (size=%u)", (unsigned int)vec.size());
    out.write(buf, strlen(buf));
    return out;
}

// Template rule which fires if a struct or class doesn't have operator<<
template<typename T>
inline std::ostream& operator<<(std::ostream& out,const T&) {return out;}

Register_Class(DNSPacket);

DNSPacket::DNSPacket(const char *name, int kind) : ::cPacket(name,kind)
{
    this->id_var = 0;
    this->options_var = 0;
    this->qdcount_var = 0;
    this->ancount_var = 0;
    this->nscount_var = 0;
    this->arcount_var = 0;
    questions_arraysize = 0;
    this->questions_var = 0;
    answers_arraysize = 0;
    this->answers_var = 0;
    authorities_arraysize = 0;
    this->authorities_var = 0;
    additional_arraysize = 0;
    this->additional_var = 0;
}

DNSPacket::DNSPacket(const DNSPacket& other) : ::cPacket(other)
{
    questions_arraysize = 0;
    this->questions_var = 0;
    answers_arraysize = 0;
    this->answers_var = 0;
    authorities_arraysize = 0;
    this->authorities_var = 0;
    additional_arraysize = 0;
    this->additional_var = 0;
    copy(other);
}

DNSPacket::~DNSPacket()
{
    delete [] questions_var;
    delete [] answers_var;
    delete [] authorities_var;
    delete [] additional_var;
}

DNSPacket& DNSPacket::operator=(const DNSPacket& other)
{
    if (this==&other) return *this;
    ::cPacket::operator=(other);
    copy(other);
    return *this;
}

void DNSPacket::copy(const DNSPacket& other)
{
    this->id_var = other.id_var;
    this->options_var = other.options_var;
    this->qdcount_var = other.qdcount_var;
    this->ancount_var = other.ancount_var;
    this->nscount_var = other.nscount_var;
    this->arcount_var = other.arcount_var;
    delete [] this->questions_var;
    this->questions_var = (other.questions_arraysize==0) ? NULL : new DNSQuestion[other.questions_arraysize];
    questions_arraysize = other.questions_arraysize;
    for (short i=0; i<questions_arraysize; i++)
        this->questions_var[i] = other.questions_var[i];
    delete [] this->answers_var;
    this->answers_var = (other.answers_arraysize==0) ? NULL : new DNSRecord[other.answers_arraysize];
    answers_arraysize = other.answers_arraysize;
    for (short i=0; i<answers_arraysize; i++)
        this->answers_var[i] = other.answers_var[i];
    delete [] this->authorities_var;
    this->authorities_var = (other.authorities_arraysize==0) ? NULL : new DNSRecord[other.authorities_arraysize];
    authorities_arraysize = other.authorities_arraysize;
    for (short i=0; i<authorities_arraysize; i++)
        this->authorities_var[i] = other.authorities_var[i];
    delete [] this->additional_var;
    this->additional_var = (other.additional_arraysize==0) ? NULL : new DNSRecord[other.additional_arraysize];
    additional_arraysize = other.additional_arraysize;
    for (short i=0; i<additional_arraysize; i++)
        this->additional_var[i] = other.additional_var[i];
}

void DNSPacket::parsimPack(cCommBuffer *b)
{
    ::cPacket::parsimPack(b);
    doPacking(b,this->id_var);
    doPacking(b,this->options_var);
    doPacking(b,this->qdcount_var);
    doPacking(b,this->ancount_var);
    doPacking(b,this->nscount_var);
    doPacking(b,this->arcount_var);
    b->pack(questions_arraysize);
    doPacking(b,this->questions_var,questions_arraysize);
    b->pack(answers_arraysize);
    doPacking(b,this->answers_var,answers_arraysize);
    b->pack(authorities_arraysize);
    doPacking(b,this->authorities_var,authorities_arraysize);
    b->pack(additional_arraysize);
    doPacking(b,this->additional_var,additional_arraysize);
}

void DNSPacket::parsimUnpack(cCommBuffer *b)
{
    ::cPacket::parsimUnpack(b);
    doUnpacking(b,this->id_var);
    doUnpacking(b,this->options_var);
    doUnpacking(b,this->qdcount_var);
    doUnpacking(b,this->ancount_var);
    doUnpacking(b,this->nscount_var);
    doUnpacking(b,this->arcount_var);
    delete [] this->questions_var;
    b->unpack(questions_arraysize);
    if (questions_arraysize==0) {
        this->questions_var = 0;
    } else {
        this->questions_var = new DNSQuestion[questions_arraysize];
        doUnpacking(b,this->questions_var,questions_arraysize);
    }
    delete [] this->answers_var;
    b->unpack(answers_arraysize);
    if (answers_arraysize==0) {
        this->answers_var = 0;
    } else {
        this->answers_var = new DNSRecord[answers_arraysize];
        doUnpacking(b,this->answers_var,answers_arraysize);
    }
    delete [] this->authorities_var;
    b->unpack(authorities_arraysize);
    if (authorities_arraysize==0) {
        this->authorities_var = 0;
    } else {
        this->authorities_var = new DNSRecord[authorities_arraysize];
        doUnpacking(b,this->authorities_var,authorities_arraysize);
    }
    delete [] this->additional_var;
    b->unpack(additional_arraysize);
    if (additional_arraysize==0) {
        this->additional_var = 0;
    } else {
        this->additional_var = new DNSRecord[additional_arraysize];
        doUnpacking(b,this->additional_var,additional_arraysize);
    }
}

unsigned short DNSPacket::getId() const
{
    return id_var;
}

void DNSPacket::setId(unsigned short id)
{
    this->id_var = id;
}

unsigned short DNSPacket::getOptions() const
{
    return options_var;
}

void DNSPacket::setOptions(unsigned short options)
{
    this->options_var = options;
}

unsigned short DNSPacket::getQdcount() const
{
    return qdcount_var;
}

void DNSPacket::setQdcount(unsigned short qdcount)
{
    this->qdcount_var = qdcount;
}

unsigned short DNSPacket::getAncount() const
{
    return ancount_var;
}

void DNSPacket::setAncount(unsigned short ancount)
{
    this->ancount_var = ancount;
}

unsigned short DNSPacket::getNscount() const
{
    return nscount_var;
}

void DNSPacket::setNscount(unsigned short nscount)
{
    this->nscount_var = nscount;
}

unsigned short DNSPacket::getArcount() const
{
    return arcount_var;
}

void DNSPacket::setArcount(unsigned short arcount)
{
    this->arcount_var = arcount;
}

void DNSPacket::setNumQuestions(short size)
{
    DNSQuestion *questions_var2 = (size==0) ? NULL : new DNSQuestion[size];
    short sz = questions_arraysize < size ? questions_arraysize : size;
    for (short i=0; i<sz; i++)
        questions_var2[i] = this->questions_var[i];
    questions_arraysize = size;
    delete [] this->questions_var;
    this->questions_var = questions_var2;
}

short DNSPacket::getNumQuestions() const
{
    return questions_arraysize;
}

DNSQuestion& DNSPacket::getQuestions(short k)
{
    if (k>=questions_arraysize) throw cRuntimeError("Array of size %d indexed by %d", questions_arraysize, k);
    return questions_var[k];
}

void DNSPacket::setQuestions(short k, const DNSQuestion& questions)
{
    if (k>=questions_arraysize) throw cRuntimeError("Array of size %d indexed by %d", questions_arraysize, k);
    this->questions_var[k] = questions;
}

void DNSPacket::setNumAnswers(short size)
{
    DNSRecord *answers_var2 = (size==0) ? NULL : new DNSRecord[size];
    short sz = answers_arraysize < size ? answers_arraysize : size;
    for (short i=0; i<sz; i++)
        answers_var2[i] = this->answers_var[i];
    answers_arraysize = size;
    delete [] this->answers_var;
    this->answers_var = answers_var2;
}

short DNSPacket::getNumAnswers() const
{
    return answers_arraysize;
}

DNSRecord& DNSPacket::getAnswers(short k)
{
    if (k>=answers_arraysize) throw cRuntimeError("Array of size %d indexed by %d", answers_arraysize, k);
    return answers_var[k];
}

void DNSPacket::setAnswers(short k, const DNSRecord& answers)
{
    if (k>=answers_arraysize) throw cRuntimeError("Array of size %d indexed by %d", answers_arraysize, k);
    this->answers_var[k] = answers;
}

void DNSPacket::setNumAuthorities(short size)
{
    DNSRecord *authorities_var2 = (size==0) ? NULL : new DNSRecord[size];
    short sz = authorities_arraysize < size ? authorities_arraysize : size;
    for (short i=0; i<sz; i++)
        authorities_var2[i] = this->authorities_var[i];
    authorities_arraysize = size;
    delete [] this->authorities_var;
    this->authorities_var = authorities_var2;
}

short DNSPacket::getNumAuthorities() const
{
    return authorities_arraysize;
}

DNSRecord& DNSPacket::getAuthorities(short k)
{
    if (k>=authorities_arraysize) throw cRuntimeError("Array of size %d indexed by %d", authorities_arraysize, k);
    return authorities_var[k];
}

void DNSPacket::setAuthorities(short k, const DNSRecord& authorities)
{
    if (k>=authorities_arraysize) throw cRuntimeError("Array of size %d indexed by %d", authorities_arraysize, k);
    this->authorities_var[k] = authorities;
}

void DNSPacket::setNumAdditional(short size)
{
    DNSRecord *additional_var2 = (size==0) ? NULL : new DNSRecord[size];
    short sz = additional_arraysize < size ? additional_arraysize : size;
    for (short i=0; i<sz; i++)
        additional_var2[i] = this->additional_var[i];
    additional_arraysize = size;
    delete [] this->additional_var;
    this->additional_var = additional_var2;
}

short DNSPacket::getNumAdditional() const
{
    return additional_arraysize;
}

DNSRecord& DNSPacket::getAdditional(short k)
{
    if (k>=additional_arraysize) throw cRuntimeError("Array of size %d indexed by %d", additional_arraysize, k);
    return additional_var[k];
}

void DNSPacket::setAdditional(short k, const DNSRecord& additional)
{
    if (k>=additional_arraysize) throw cRuntimeError("Array of size %d indexed by %d", additional_arraysize, k);
    this->additional_var[k] = additional;
}

class DNSPacketDescriptor : public cClassDescriptor
{
  public:
    DNSPacketDescriptor();
    virtual ~DNSPacketDescriptor();

    virtual bool doesSupport(cObject *obj) const;
    virtual const char *getProperty(const char *propertyname) const;
    virtual int getFieldCount(void *object) const;
    virtual const char *getFieldName(void *object, int field) const;
    virtual int findField(void *object, const char *fieldName) const;
    virtual unsigned int getFieldTypeFlags(void *object, int field) const;
    virtual const char *getFieldTypeString(void *object, int field) const;
    virtual const char *getFieldProperty(void *object, int field, const char *propertyname) const;
    virtual int getArraySize(void *object, int field) const;

    virtual std::string getFieldAsString(void *object, int field, int i) const;
    virtual bool setFieldAsString(void *object, int field, int i, const char *value) const;

    virtual const char *getFieldStructName(void *object, int field) const;
    virtual void *getFieldStructPointer(void *object, int field, int i) const;
};

Register_ClassDescriptor(DNSPacketDescriptor);

DNSPacketDescriptor::DNSPacketDescriptor() : cClassDescriptor("DNSPacket", "cPacket")
{
}

DNSPacketDescriptor::~DNSPacketDescriptor()
{
}

bool DNSPacketDescriptor::doesSupport(cObject *obj) const
{
    return dynamic_cast<DNSPacket *>(obj)!=NULL;
}

const char *DNSPacketDescriptor::getProperty(const char *propertyname) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : NULL;
}

int DNSPacketDescriptor::getFieldCount(void *object) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    return basedesc ? 10+basedesc->getFieldCount(object) : 10;
}

unsigned int DNSPacketDescriptor::getFieldTypeFlags(void *object, int field) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getFieldTypeFlags(object, field);
        field -= basedesc->getFieldCount(object);
    }
    static unsigned int fieldTypeFlags[] = {
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISARRAY | FD_ISCOMPOUND,
        FD_ISARRAY | FD_ISCOMPOUND,
        FD_ISARRAY | FD_ISCOMPOUND,
        FD_ISARRAY | FD_ISCOMPOUND,
    };
    return (field>=0 && field<10) ? fieldTypeFlags[field] : 0;
}

const char *DNSPacketDescriptor::getFieldName(void *object, int field) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getFieldName(object, field);
        field -= basedesc->getFieldCount(object);
    }
    static const char *fieldNames[] = {
        "id",
        "options",
        "qdcount",
        "ancount",
        "nscount",
        "arcount",
        "questions",
        "answers",
        "authorities",
        "additional",
    };
    return (field>=0 && field<10) ? fieldNames[field] : NULL;
}

int DNSPacketDescriptor::findField(void *object, const char *fieldName) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    int base = basedesc ? basedesc->getFieldCount(object) : 0;
    if (fieldName[0]=='i' && strcmp(fieldName, "id")==0) return base+0;
    if (fieldName[0]=='o' && strcmp(fieldName, "options")==0) return base+1;
    if (fieldName[0]=='q' && strcmp(fieldName, "qdcount")==0) return base+2;
    if (fieldName[0]=='a' && strcmp(fieldName, "ancount")==0) return base+3;
    if (fieldName[0]=='n' && strcmp(fieldName, "nscount")==0) return base+4;
    if (fieldName[0]=='a' && strcmp(fieldName, "arcount")==0) return base+5;
    if (fieldName[0]=='q' && strcmp(fieldName, "questions")==0) return base+6;
    if (fieldName[0]=='a' && strcmp(fieldName, "answers")==0) return base+7;
    if (fieldName[0]=='a' && strcmp(fieldName, "authorities")==0) return base+8;
    if (fieldName[0]=='a' && strcmp(fieldName, "additional")==0) return base+9;
    return basedesc ? basedesc->findField(object, fieldName) : -1;
}

const char *DNSPacketDescriptor::getFieldTypeString(void *object, int field) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getFieldTypeString(object, field);
        field -= basedesc->getFieldCount(object);
    }
    static const char *fieldTypeStrings[] = {
        "unsigned short",
        "unsigned short",
        "unsigned short",
        "unsigned short",
        "unsigned short",
        "unsigned short",
        "DNSQuestion",
        "DNSRecord",
        "DNSRecord",
        "DNSRecord",
    };
    return (field>=0 && field<10) ? fieldTypeStrings[field] : NULL;
}

const char *DNSPacketDescriptor::getFieldProperty(void *object, int field, const char *propertyname) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getFieldProperty(object, field, propertyname);
        field -= basedesc->getFieldCount(object);
    }
    switch (field) {
        case 6:
            if (!strcmp(propertyname,"sizeGetter")) return "getNumQuestions";
            if (!strcmp(propertyname,"sizeSetter")) return "setNumQuestions";
            if (!strcmp(propertyname,"sizetype")) return "short";
            return NULL;
        case 7:
            if (!strcmp(propertyname,"sizeGetter")) return "getNumAnswers";
            if (!strcmp(propertyname,"sizeSetter")) return "setNumAnswers";
            if (!strcmp(propertyname,"sizetype")) return "short";
            return NULL;
        case 8:
            if (!strcmp(propertyname,"sizeGetter")) return "getNumAuthorities";
            if (!strcmp(propertyname,"sizeSetter")) return "setNumAuthorities";
            if (!strcmp(propertyname,"sizetype")) return "short";
            return NULL;
        case 9:
            if (!strcmp(propertyname,"sizeGetter")) return "getNumAdditional";
            if (!strcmp(propertyname,"sizeSetter")) return "setNumAdditional";
            if (!strcmp(propertyname,"sizetype")) return "short";
            return NULL;
        default: return NULL;
    }
}

int DNSPacketDescriptor::getArraySize(void *object, int field) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getArraySize(object, field);
        field -= basedesc->getFieldCount(object);
    }
    DNSPacket *pp = (DNSPacket *)object; (void)pp;
    switch (field) {
        case 6: return pp->getNumQuestions();
        case 7: return pp->getNumAnswers();
        case 8: return pp->getNumAuthorities();
        case 9: return pp->getNumAdditional();
        default: return 0;
    }
}

std::string DNSPacketDescriptor::getFieldAsString(void *object, int field, int i) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getFieldAsString(object,field,i);
        field -= basedesc->getFieldCount(object);
    }
    DNSPacket *pp = (DNSPacket *)object; (void)pp;
    switch (field) {
        case 0: return ulong2string(pp->getId());
        case 1: return ulong2string(pp->getOptions());
        case 2: return ulong2string(pp->getQdcount());
        case 3: return ulong2string(pp->getAncount());
        case 4: return ulong2string(pp->getNscount());
        case 5: return ulong2string(pp->getArcount());
        case 6: {std::stringstream out; out << pp->getQuestions(i); return out.str();}
        case 7: {std::stringstream out; out << pp->getAnswers(i); return out.str();}
        case 8: {std::stringstream out; out << pp->getAuthorities(i); return out.str();}
        case 9: {std::stringstream out; out << pp->getAdditional(i); return out.str();}
        default: return "";
    }
}

bool DNSPacketDescriptor::setFieldAsString(void *object, int field, int i, const char *value) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->setFieldAsString(object,field,i,value);
        field -= basedesc->getFieldCount(object);
    }
    DNSPacket *pp = (DNSPacket *)object; (void)pp;
    switch (field) {
        case 0: pp->setId(string2ulong(value)); return true;
        case 1: pp->setOptions(string2ulong(value)); return true;
        case 2: pp->setQdcount(string2ulong(value)); return true;
        case 3: pp->setAncount(string2ulong(value)); return true;
        case 4: pp->setNscount(string2ulong(value)); return true;
        case 5: pp->setArcount(string2ulong(value)); return true;
        default: return false;
    }
}

const char *DNSPacketDescriptor::getFieldStructName(void *object, int field) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getFieldStructName(object, field);
        field -= basedesc->getFieldCount(object);
    }
    switch (field) {
        case 6: return opp_typename(typeid(DNSQuestion));
        case 7: return opp_typename(typeid(DNSRecord));
        case 8: return opp_typename(typeid(DNSRecord));
        case 9: return opp_typename(typeid(DNSRecord));
        default: return NULL;
    };
}

void *DNSPacketDescriptor::getFieldStructPointer(void *object, int field, int i) const
{
    cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount(object))
            return basedesc->getFieldStructPointer(object, field, i);
        field -= basedesc->getFieldCount(object);
    }
    DNSPacket *pp = (DNSPacket *)object; (void)pp;
    switch (field) {
        case 6: return (void *)(&pp->getQuestions(i)); break;
        case 7: return (void *)(&pp->getAnswers(i)); break;
        case 8: return (void *)(&pp->getAuthorities(i)); break;
        case 9: return (void *)(&pp->getAdditional(i)); break;
        default: return NULL;
    }
}


