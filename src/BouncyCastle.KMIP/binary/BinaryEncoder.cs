using System;

namespace org.bouncycastle.kmip.wire.binary
{

	using Strings = org.bouncycastle.util.Strings;

	public class BinaryEncoder : KMIPEncoder
	{
		private readonly OutputStream @out;

		public BinaryEncoder(OutputStream @out)
		{
			this.@out = @out;
		}

		public virtual void output(KMIPEncodable kmipEncodable)
		{
			writeItem(kmipEncodable.toKMIPItem());
		}

		private void writeItem(KMIPItem item)
		{
			writeTag(item.getTag());

			@out.write(item.getType());

			long length = item.getLength();

			writeLength(length);

			switch (item.getType())
			{
			case KMIPType.BIG_INTEGER:
				byte[] bigInt = ((BigInteger)item.getValue()).toByteArray();

				int padLength = (int)(length - bigInt.Length);
				if (padLength != 0)
				{
					byte pad = (byte)((bigInt[0] < 0) ? 0xff : 0x00);

					for (int p = 0; p != padLength; p++)
					{
						@out.write(pad);
					}
				}
				@out.write(bigInt);
				break;
			case KMIPType.BOOLEAN:
				writeLong(((bool?)item.getValue()).Value ? 0x01 : 0x00);
				break;
			case KMIPType.BYTE_STRING:
				@out.write(((byte[])item.getValue()));
				writePadFor(length);
				break;
			case KMIPType.DATE_TIME:
				writeLong(((DateTime)item.getValue()).Ticks);
				break;
			case KMIPType.ENUMERATION:
				writeInt(((int?)item.getValue()).Value);
				break;
			case KMIPType.INTEGER:
				writeInt(((int?)item.getValue()).Value);
				break;
			case KMIPType.INTERVAL:
				writeInt(((long?)item.getValue()).Value);
				break;
			case KMIPType.LONG_INTEGER:
				writeLong(((long?)item.getValue()).Value);
				break;
			case KMIPType.STRUCTURE:
				for (Iterator it = ((List)item.getValue()).iterator(); it.hasNext();)
				{
					writeItem((KMIPItem)it.next());
				}
				break;
			case KMIPType.TEXT_STRING:
				@out.write(Strings.toUTF8ByteArray((string)item.getValue()));
				writePadFor(length);
				break;
			}
		}

		private void writeLong(long l)
		{
			@out.write((int)(l >> 56));
			@out.write((int)(l >> 48));
			@out.write((int)(l >> 40));
			@out.write((int)(l >> 32));
			@out.write((int)(l >> 24));
			@out.write((int)(l >> 16));
			@out.write((int)(l >> 8));
			@out.write((int)l);
		}

		private void writeInt(int i)
		{
			@out.write(i >> 24);
			@out.write(i >> 16);
			@out.write(i >> 8);
			@out.write(i);

			@out.write(0); // padding
			@out.write(0);
			@out.write(0);
			@out.write(0);
		}

		private void writeTag(int tag)
		{
			@out.write(tag >> 16);
			@out.write(tag >> 8);
			@out.write(tag);
		}

		private void writeLength(long length)
		{
			@out.write((int)(length >> 24));
			@out.write((int)(length >> 16));
			@out.write((int)(length >> 8));
			@out.write((int)length);
		}

		private void writePadFor(long length)
		{
			int padLength = 8 - (int)(length % 8);
			if (padLength != 8)
			{
				for (int p = 0; p != padLength; p++)
				{
					@out.write(0);
				}
			}
		}
	}

}