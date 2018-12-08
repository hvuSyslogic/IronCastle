using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Stream that produces output based on the default encoding for the passed in objects.
	/// </summary>
	public class ASN1OutputStream
	{
		private OutputStream os;

		public ASN1OutputStream(OutputStream os)
		{
			this.os = os;
		}

		public virtual void writeLength(int length)
		{
			if (length > 127)
			{
				int size = 1;
				int val = length;

				while ((val = (int)((uint)val >> 8)) != 0)
				{
					size++;
				}

				write(unchecked((byte)(size | 0x80)));

				for (int i = (size - 1) * 8; i >= 0; i -= 8)
				{
					write((byte)(length >> i));
				}
			}
			else
			{
				write((byte)length);
			}
		}

		public virtual void write(int b)
		{
			os.write(b);
		}

		public virtual void write(byte[] bytes)
		{
			os.write(bytes);
		}

		public virtual void write(byte[] bytes, int off, int len)
		{
			os.write(bytes, off, len);
		}

		public virtual void writeEncoded(int tag, byte[] bytes)
		{
			write(tag);
			writeLength(bytes.Length);
			write(bytes);
		}

		public virtual void writeTag(int flags, int tagNo)
		{
			if (tagNo < 31)
			{
				write(flags | tagNo);
			}
			else
			{
				write(flags | 0x1f);
				if (tagNo < 128)
				{
					write(tagNo);
				}
				else
				{
					byte[] stack = new byte[5];
					int pos = stack.Length;

					stack[--pos] = (byte)(tagNo & 0x7F);

					do
					{
						tagNo >>= 7;
						stack[--pos] = unchecked((byte)(tagNo & 0x7F | 0x80));
					} while (tagNo > 127);

					write(stack, pos, stack.Length - pos);
				}
			}
		}

		public virtual void writeEncoded(int flags, int tagNo, byte[] bytes)
		{
			writeTag(flags, tagNo);
			writeLength(bytes.Length);
			write(bytes);
		}

		public virtual void writeNull()
		{
			os.write(BERTags_Fields.NULL);
			os.write(0x00);
		}

		public virtual void writeObject(ASN1Encodable obj)
		{
			if (obj != null)
			{
				obj.toASN1Primitive().encode(this);
			}
			else
			{
				throw new IOException("null object detected");
			}
		}

		public virtual void writeImplicitObject(ASN1Primitive obj)
		{
			if (obj != null)
			{
				obj.encode(new ImplicitOutputStream(this, os));
			}
			else
			{
				throw new IOException("null object detected");
			}
		}

		public virtual void close()
		{
			os.close();
		}

		public virtual void flush()
		{
			os.flush();
		}

		public virtual ASN1OutputStream getDERSubStream()
		{
			return new DEROutputStream(os);
		}

		public virtual ASN1OutputStream getDLSubStream()
		{
			return new DLOutputStream(os);
		}

		public class ImplicitOutputStream : ASN1OutputStream
		{
			private readonly ASN1OutputStream outerInstance;

			internal bool first = true;

			public ImplicitOutputStream(ASN1OutputStream outerInstance, OutputStream os) : base(os)
			{
				this.outerInstance = outerInstance;
			}

			public override void write(int b)
			{
				if (first)
				{
					first = false;
				}
				else
				{
					base.write(b);
				}
			}
		}
	}

}