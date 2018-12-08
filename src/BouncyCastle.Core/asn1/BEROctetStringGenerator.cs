using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A generator for indefinite-length OCTET STRINGs
	/// </summary>
	public class BEROctetStringGenerator : BERGenerator
	{
		/// <summary>
		/// Use the passed in stream as the target for the generator, writing out the header tag
		/// for a constructed OCTET STRING.
		/// </summary>
		/// <param name="out"> target stream </param>
		/// <exception cref="IOException"> if the target stream cannot be written to. </exception>
		public BEROctetStringGenerator(OutputStream @out) : base(@out)
		{

			writeBERHeader(BERTags_Fields.CONSTRUCTED | BERTags_Fields.OCTET_STRING);
		}

		/// <summary>
		/// Use the passed in stream as the target for the generator, writing out the header tag
		/// for a tagged constructed OCTET STRING (possibly implicit).
		/// </summary>
		/// <param name="out"> target stream </param>
		/// <param name="tagNo"> the tag number to introduce </param>
		/// <param name="isExplicit"> true if this is an explicitly tagged object, false otherwise. </param>
		/// <exception cref="IOException"> if the target stream cannot be written to. </exception>
		public BEROctetStringGenerator(OutputStream @out, int tagNo, bool isExplicit) : base(@out, tagNo, isExplicit)
		{

			writeBERHeader(BERTags_Fields.CONSTRUCTED | BERTags_Fields.OCTET_STRING);
		}

		/// <summary>
		/// Return a stream representing the content target for this OCTET STRING
		/// </summary>
		/// <returns> an OutputStream which chunks data in blocks of 1000 (CER limit). </returns>
		public virtual OutputStream getOctetOutputStream()
		{
			return getOctetOutputStream(new byte[1000]); // limit for CER encoding.
		}

		/// <summary>
		/// Return a stream representing the content target for this OCTET STRING
		/// </summary>
		/// <param name="buf"> the buffer to use for chunking the data. </param>
		/// <returns> an OutputStream which chunks data in blocks of buf length. </returns>
		public virtual OutputStream getOctetOutputStream(byte[] buf)
		{
			return new BufferedBEROctetStream(this, buf);
		}

		public class BufferedBEROctetStream : OutputStream
		{
			private readonly BEROctetStringGenerator outerInstance;

			internal byte[] _buf;
			internal int _off;
			internal DEROutputStream _derOut;

			public BufferedBEROctetStream(BEROctetStringGenerator outerInstance, byte[] buf)
			{
				this.outerInstance = outerInstance;
				_buf = buf;
				_off = 0;
				_derOut = new DEROutputStream(outerInstance._out);
			}

			public virtual void write(int b)
			{
				_buf[_off++] = (byte)b;

				if (_off == _buf.Length)
				{
					DEROctetString.encode(_derOut, _buf);
					_off = 0;
				}
			}

			public virtual void write(byte[] b, int off, int len)
			{
				while (len > 0)
				{
					int numToCopy = Math.Min(len, _buf.Length - _off);
					JavaSystem.arraycopy(b, off, _buf, _off, numToCopy);

					_off += numToCopy;
					if (_off < _buf.Length)
					{
						break;
					}

					DEROctetString.encode(_derOut, _buf);
					_off = 0;

					off += numToCopy;
					len -= numToCopy;
				}
			}

			public virtual void close()
			{
				if (_off != 0)
				{
					byte[] bytes = new byte[_off];
					JavaSystem.arraycopy(_buf, 0, bytes, 0, _off);

					DEROctetString.encode(_derOut, bytes);
				}

				 outerInstance.writeBEREnd();
			}
		}
	}

}