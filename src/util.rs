use std::num::TryFromIntError;

use binrw::io::{Read, Seek, TakeSeekExt, Write};
use binrw::{until_eof, BinRead, BinResult, BinWriterExt, Endian};

#[derive(derive_more::From, derive_more::Error, derive_more::Display, Debug)]
pub enum WritePositionError {
    Io(binrw::io::Error),
    TryFromInt(TryFromIntError),
    BinRw(binrw::Error),
}

pub(crate) fn stream_position<S: Seek>(s: &mut S) -> Result<u16, WritePositionError> {
    Ok(u16::try_from(s.stream_position()?)?)
}

/// Write the current position of the `writer` at `output_position`, minus `offset`
/// This is used to get the length of a struct, via an empty field at the end
pub(crate) fn write_position_at<W: Write + Seek>(
    writer: &mut W,
    output_position: u16,
    offset: u16,
) -> Result<(), WritePositionError> {
    // TODO: avoid unwrap
    let current_position = u16::try_from(writer.stream_position()?)?;
    writer.seek(std::io::SeekFrom::Start(output_position.into()))?;
    writer.write_be(&(current_position - offset))?;
    Ok(())
}

pub(crate) fn until_limit<Reader, T, Arg, Ret>(
    limit: u64,
) -> impl Fn(&mut Reader, Endian, Arg) -> BinResult<Ret> + Copy
where
    T: for<'a> BinRead<Args<'a> = Arg>,
    Reader: Read + Seek,
    Arg: Clone,
    Ret: FromIterator<T>,
{
    move |reader, endian, args| until_eof(&mut reader.take_seek(limit), endian, args)
}
