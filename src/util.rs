use binrw::io::{Read, Seek, TakeSeekExt};
use binrw::{until_eof, BinRead, BinResult, Endian};

pub(crate) trait WriteSize {
    type Arg;

    fn write_size(&self, arg: Self::Arg) -> Result<u16, String>;
}

impl<T: WriteSize> WriteSize for Vec<T>
where
    <T as WriteSize>::Arg: Clone,
{
    type Arg = <T as WriteSize>::Arg;

    fn write_size(&self, arg: Self::Arg) -> Result<u16, String> {
        let mut size = 0;

        for element in self {
            size += element.write_size(arg.clone())?;
        }

        Ok(size)
    }
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
