use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::io::{Seek, SeekFrom};

#[derive(Debug)]
struct EcoffFileHeader {
    f_magic: u16,
    f_nscns: u16,
    f_timdat: u32,
    f_symptr: u32,
    f_nsyms: u32,
    f_opthdr: u16,
    f_flags: u16,
}

#[derive(Debug)]
struct EcoffOptionalHeader {
    magic: u16,
    vstamp: u16,
    tsize: u32,
    dsize: u32,
    bsize: u32,
    entry: u32,
    text_start: u32,
    data_start: u32,
    bss_start: u32,
    gprmask: u32,
    cprmask: [u32; 4],
    gp_value: u32,
}

fn read_file_header<R: Read>(reader: &mut R) -> io::Result<EcoffFileHeader> {
    Ok(EcoffFileHeader {
        f_magic: reader.read_u16::<BigEndian>()?,
        f_nscns: reader.read_u16::<BigEndian>()?,
        f_timdat: reader.read_u32::<BigEndian>()?,
        f_symptr: reader.read_u32::<BigEndian>()?,
        f_nsyms: reader.read_u32::<BigEndian>()?,
        f_opthdr: reader.read_u16::<BigEndian>()?,
        f_flags: reader.read_u16::<BigEndian>()?,
    })
}

fn read_optional_header<R: Read>(reader: &mut R) -> io::Result<EcoffOptionalHeader> {
    Ok(EcoffOptionalHeader {
        magic: reader.read_u16::<BigEndian>()?,
        vstamp: reader.read_u16::<BigEndian>()?,
        tsize: reader.read_u32::<BigEndian>()?,
        dsize: reader.read_u32::<BigEndian>()?,
        bsize: reader.read_u32::<BigEndian>()?,
        entry: reader.read_u32::<BigEndian>()?,
        text_start: reader.read_u32::<BigEndian>()?,
        data_start: reader.read_u32::<BigEndian>()?,
        bss_start: reader.read_u32::<BigEndian>()?,
        gprmask: reader.read_u32::<BigEndian>()?,
        cprmask: [
            reader.read_u32::<BigEndian>()?,
            reader.read_u32::<BigEndian>()?,
            reader.read_u32::<BigEndian>()?,
            reader.read_u32::<BigEndian>()?,
        ],
        gp_value: reader.read_u32::<BigEndian>()?,
    })
}

#[derive(Debug)]
struct EcoffSectionHeader {
    s_name: [u8; 8],
    s_paddr: u32,
    s_vaddr: u32,
    s_size: u32,
    s_scnptr: u32,
    s_relptr: u32,
    s_lnnoptr: u32,
    s_nreloc: u16,
    s_nlnno: u16,
    s_flags: u32,
}

fn read_section_header<R: Read>(reader: &mut R) -> io::Result<EcoffSectionHeader> {
    let mut s_name = [0u8; 8];
    reader.read_exact(&mut s_name)?;

    Ok(EcoffSectionHeader {
        s_name,
        s_paddr: reader.read_u32::<BigEndian>()?,
        s_vaddr: reader.read_u32::<BigEndian>()?,
        s_size: reader.read_u32::<BigEndian>()?,
        s_scnptr: reader.read_u32::<BigEndian>()?,
        s_relptr: reader.read_u32::<BigEndian>()?,
        s_lnnoptr: reader.read_u32::<BigEndian>()?,
        s_nreloc: reader.read_u16::<BigEndian>()?,
        s_nlnno: reader.read_u16::<BigEndian>()?,
        s_flags: reader.read_u32::<BigEndian>()?,
    })
}

fn read_section_data<R: Read + Seek>(
    reader: &mut BufReader<R>,
    header: &EcoffSectionHeader,
) -> io::Result<Vec<u8>> {
    let mut data = vec![0; header.s_size as usize];
    reader.seek(SeekFrom::Start(header.s_scnptr as u64))?;
    reader.read_exact(&mut data)?;
    Ok(data)
}
#[derive(Debug)]
struct SymbolHeader {
    magic: u16,
    vstamp: u16,
    iline_max: u32,
    cb_line: u32,
    cb_line_offset: u32,
    idn_max: u32,
    cb_dn_offset: u32,
    ipd_max: u32,
    cb_pd_offset: u32,
    isym_max: u32,
    cb_sym_offset: u32, // Byte offset to start of local symbols.
    iopt_max: u32,
    cb_opt_offset: u32,
    iaux_max: u32,
    cb_aux_offset: u32,
    iss_max: u32, // Byte size of local string table
    cb_ss_offset: u32,
    iss_ext_max: u32,
    cb_ss_ext_offset: u32,
    ifd_max: u32,
    cb_fd_offset: u32,
    crfd: u32,
    cb_rfd_offset: u32,
    iext_max: u32,
    cb_ext_offset: u32,
    // Machine dependent fields go here if needed
}

fn read_symbol_header<R: Read>(reader: &mut R) -> io::Result<SymbolHeader> {
    Ok(SymbolHeader {
        magic: reader.read_u16::<BigEndian>()?,
        vstamp: reader.read_u16::<BigEndian>()?,
        iline_max: reader.read_u32::<BigEndian>()?,
        cb_line: reader.read_u32::<BigEndian>()?,
        cb_line_offset: reader.read_u32::<BigEndian>()?,
        idn_max: reader.read_u32::<BigEndian>()?,
        cb_dn_offset: reader.read_u32::<BigEndian>()?,
        ipd_max: reader.read_u32::<BigEndian>()?,
        cb_pd_offset: reader.read_u32::<BigEndian>()?,
        isym_max: reader.read_u32::<BigEndian>()?,
        cb_sym_offset: reader.read_u32::<BigEndian>()?,
        iopt_max: reader.read_u32::<BigEndian>()?,
        cb_opt_offset: reader.read_u32::<BigEndian>()?,
        iaux_max: reader.read_u32::<BigEndian>()?,
        cb_aux_offset: reader.read_u32::<BigEndian>()?,
        iss_max: reader.read_u32::<BigEndian>()?, // Byte size of local string table.
        cb_ss_offset: reader.read_u32::<BigEndian>()?, // Byte offset to start of local strings.
        iss_ext_max: reader.read_u32::<BigEndian>()?, // Byte size of external string table.
        cb_ss_ext_offset: reader.read_u32::<BigEndian>()?, // Byte offset to start of external strings.
        ifd_max: reader.read_u32::<BigEndian>()?,
        cb_fd_offset: reader.read_u32::<BigEndian>()?, // Byte offset to start of file descriptors.
        crfd: reader.read_u32::<BigEndian>()?,
        cb_rfd_offset: reader.read_u32::<BigEndian>()?,
        iext_max: reader.read_u32::<BigEndian>()?, // Number of file descriptors.
        cb_ext_offset: reader.read_u32::<BigEndian>()?, // Byte offset to start of external strings.
    })
}

// https://web.archive.org/web/20160305114748/http://h41361.www4.hp.com/docs/base_doc/DOCUMENTATION/V50A_ACRO_SUP/OBJSPEC.PDF
fn main() -> io::Result<()> {
    let mut file = File::open("/home/d/decomp-toolkit/libapi/a09.o")?;
    let mut reader = BufReader::new(file);

    // Read the file header
    let file_header = read_file_header(&mut reader)?;
    println!("ECOFF File Header: {:?}", file_header);

    // Read the optional header if present
    if file_header.f_opthdr > 0 {
        let optional_header = read_optional_header(&mut reader)?;
        println!("ECOFF Optional Header: {:?}", optional_header);
    }

    // Read and print each section header
    for _ in 0..file_header.f_nscns {
        let section_header = read_section_header(&mut reader)?;
        let string = String::from_utf8_lossy(&section_header.s_name);
        println!("{}", string);
        println!("ECOFF Section Header: {:?}", section_header);
        let section_data = read_section_data(&mut reader, &section_header)?;
        println!("section data {:?}", section_data);
    }

    reader.seek(SeekFrom::Start(file_header.f_symptr as u64))?;

    let symbol_header = read_symbol_header(&mut reader)?;
    println!("{:?}", symbol_header);

    {
        // "The storage format for the string table is a list of null-terminated character strings. It is correctly
        // considered as one long character array, not an array of strings. Fields in the symbolic header and file
        // headers represent string table sizes and offsets in bytes."

        // read local strings
        let mut data = vec![0; symbol_header.iss_max as usize];
        reader.seek(SeekFrom::Start(symbol_header.cb_ss_offset as u64))?;
        reader.read_exact(&mut data)?;

        let string = String::from_utf8_lossy(&data);

        println!("local strings {:?}", string);
    }

    {
        // read external strings
        let mut data = vec![0; symbol_header.iss_ext_max as usize];
        reader.seek(SeekFrom::Start(symbol_header.cb_ss_ext_offset as u64))?;
        reader.read_exact(&mut data)?;

        let string = String::from_utf8_lossy(&data);

        println!("external strings {:?}", string);
    }

    Ok(())
}
