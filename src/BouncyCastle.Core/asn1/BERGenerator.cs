using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Base class for generators for indefinite-length structures.
	/// </summary>
	public class BERGenerator : ASN1Generator
	{
		private bool _tagged = false;
		private bool _isExplicit;
		private int _tagNo;

		public BERGenerator(OutputStream @out) : base(@out)
		{
		}

		public BERGenerator(OutputStream @out, int tagNo, bool isExplicit) : base(@out)
		{

			_tagged = true;
			_isExplicit = isExplicit;
			_tagNo = tagNo;
		}

		public override OutputStream getRawOutputStream()
		{
			return _out;
		}

		private void writeHdr(int tag)
		{
			_out.write(tag);
			_out.write(0x80);
		}

		public virtual void writeBERHeader(int tag)
		{
			if (_tagged)
			{
				int tagNum = _tagNo | BERTags_Fields.TAGGED;

				if (_isExplicit)
				{
					writeHdr(tagNum | BERTags_Fields.CONSTRUCTED);
					writeHdr(tag);
				}
				else
				{
					if ((tag & BERTags_Fields.CONSTRUCTED) != 0)
					{
						writeHdr(tagNum | BERTags_Fields.CONSTRUCTED);
					}
					else
					{
						writeHdr(tagNum);
					}
				}
			}
			else
			{
				writeHdr(tag);
			}
		}

		public virtual void writeBEREnd()
		{
			_out.write(0x00);
			_out.write(0x00);

			if (_tagged && _isExplicit) // write extra end for tag header
			{
				_out.write(0x00);
				_out.write(0x00);
			}
		}
	}

}