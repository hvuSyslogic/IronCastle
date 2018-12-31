using org.bouncycastle.asn1;

using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.asn1.util
{

		
	/// <summary>
	/// Utility class for dumping ASN.1 objects as (hopefully) human friendly strings.
	/// </summary>
	public class ASN1Dump
	{
		private const string TAB = "    ";
		private const int SAMPLE_SIZE = 32;

		/// <summary>
		/// dump a DER object as a formatted string with indentation
		/// </summary>
		/// <param name="obj"> the ASN1Primitive to be dumped out. </param>
		internal static void _dumpAsString(string indent, bool verbose, ASN1Primitive obj, StringBuffer buf)
		{
			string nl = Strings.lineSeparator();
			if (obj is ASN1Sequence)
			{
				Enumeration e = ((ASN1Sequence)obj).getObjects();
				string tab = indent + TAB;

				buf.append(indent);
				if (obj is BERSequence)
				{
					buf.append("BER Sequence");
				}
				else if (obj is DERSequence)
				{
					buf.append("DER Sequence");
				}
				else
				{
					buf.append("Sequence");
				}

				buf.append(nl);

				while (e.hasMoreElements())
				{
					object o = e.nextElement();

					if (o == null || o.Equals(DERNull.INSTANCE))
					{
						buf.append(tab);
						buf.append("NULL");
						buf.append(nl);
					}
					else if (o is ASN1Primitive)
					{
						_dumpAsString(tab, verbose, (ASN1Primitive)o, buf);
					}
					else
					{
						_dumpAsString(tab, verbose, ((ASN1Encodable)o).toASN1Primitive(), buf);
					}
				}
			}
			else if (obj is ASN1TaggedObject)
			{
				string tab = indent + TAB;

				buf.append(indent);
				if (obj is BERTaggedObject)
				{
					buf.append("BER Tagged [");
				}
				else
				{
					buf.append("Tagged [");
				}

				ASN1TaggedObject o = (ASN1TaggedObject)obj;

				buf.append(Convert.ToString(o.getTagNo()));
				buf.append(']');

				if (!o.isExplicit())
				{
					buf.append(" IMPLICIT ");
				}

				buf.append(nl);

				if (o.isEmpty())
				{
					buf.append(tab);
					buf.append("EMPTY");
					buf.append(nl);
				}
				else
				{
					_dumpAsString(tab, verbose, o.getObject(), buf);
				}
			}
			else if (obj is ASN1Set)
			{
				Enumeration e = ((ASN1Set)obj).getObjects();
				string tab = indent + TAB;

				buf.append(indent);

				if (obj is BERSet)
				{
					buf.append("BER Set");
				}
				else if (obj is DERSet)
				{
					buf.append("DER Set");
				}
				else
				{
					buf.append("Set");
				}
				buf.append(nl);

				while (e.hasMoreElements())
				{
					object o = e.nextElement();

					if (o == null)
					{
						buf.append(tab);
						buf.append("NULL");
						buf.append(nl);
					}
					else if (o is ASN1Primitive)
					{
						_dumpAsString(tab, verbose, (ASN1Primitive)o, buf);
					}
					else
					{
						_dumpAsString(tab, verbose, ((ASN1Encodable)o).toASN1Primitive(), buf);
					}
				}
			}
			else if (obj is ASN1OctetString)
			{
				ASN1OctetString oct = (ASN1OctetString)obj;

				if (obj is BEROctetString)
				{
					buf.append(indent + "BER Constructed Octet String" + "[" + oct.getOctets().Length + "] ");
				}
				else
				{
					buf.append(indent + "DER Octet String" + "[" + oct.getOctets().Length + "] ");
				}
				if (verbose)
				{
					buf.append(dumpBinaryDataAsString(indent, oct.getOctets()));
				}
				else
				{
					buf.append(nl);
				}
			}
			else if (obj is ASN1ObjectIdentifier)
			{
				buf.append(indent + "ObjectIdentifier(" + ((ASN1ObjectIdentifier)obj).getId() + ")" + nl);
			}
			else if (obj is ASN1Boolean)
			{
				buf.append(indent + "Boolean(" + ((ASN1Boolean)obj).isTrue() + ")" + nl);
			}
			else if (obj is ASN1Integer)
			{
				buf.append(indent + "Integer(" + ((ASN1Integer)obj).getValue() + ")" + nl);
			}
			else if (obj is DERBitString)
			{
				DERBitString bt = (DERBitString)obj;
				buf.append(indent + "DER Bit String" + "[" + bt.getBytes().Length + ", " + bt.getPadBits() + "] ");
				if (verbose)
				{
					buf.append(dumpBinaryDataAsString(indent, bt.getBytes()));
				}
				else
				{
					buf.append(nl);
				}
			}
			else if (obj is DERIA5String)
			{
				buf.append(indent + "IA5String(" + ((DERIA5String)obj).getString() + ") " + nl);
			}
			else if (obj is DERUTF8String)
			{
				buf.append(indent + "UTF8String(" + ((DERUTF8String)obj).getString() + ") " + nl);
			}
			else if (obj is DERPrintableString)
			{
				buf.append(indent + "PrintableString(" + ((DERPrintableString)obj).getString() + ") " + nl);
			}
			else if (obj is DERVisibleString)
			{
				buf.append(indent + "VisibleString(" + ((DERVisibleString)obj).getString() + ") " + nl);
			}
			else if (obj is DERBMPString)
			{
				buf.append(indent + "BMPString(" + ((DERBMPString)obj).getString() + ") " + nl);
			}
			else if (obj is DERT61String)
			{
				buf.append(indent + "T61String(" + ((DERT61String)obj).getString() + ") " + nl);
			}
			else if (obj is DERGraphicString)
			{
				buf.append(indent + "GraphicString(" + ((DERGraphicString)obj).getString() + ") " + nl);
			}
			else if (obj is DERVideotexString)
			{
				buf.append(indent + "VideotexString(" + ((DERVideotexString)obj).getString() + ") " + nl);
			}
			else if (obj is ASN1UTCTime)
			{
				buf.append(indent + "UTCTime(" + ((ASN1UTCTime)obj).getTime() + ") " + nl);
			}
			else if (obj is ASN1GeneralizedTime)
			{
				buf.append(indent + "GeneralizedTime(" + ((ASN1GeneralizedTime)obj).getTime() + ") " + nl);
			}
			else if (obj is BERApplicationSpecific)
			{
				buf.append(outputApplicationSpecific("BER", indent, verbose, obj, nl));
			}
			else if (obj is DERApplicationSpecific)
			{
				buf.append(outputApplicationSpecific("DER", indent, verbose, obj, nl));
			}
			else if (obj is DLApplicationSpecific)
			{
				buf.append(outputApplicationSpecific("", indent, verbose, obj, nl));
			}
			else if (obj is ASN1Enumerated)
			{
				ASN1Enumerated en = (ASN1Enumerated) obj;
				buf.append(indent + "DER Enumerated(" + en.getValue() + ")" + nl);
			}
			else if (obj is ASN1External)
			{
				ASN1External ext = (ASN1External) obj;
				buf.append(indent + "External " + nl);
				string tab = indent + TAB;
				if (ext.getDirectReference() != null)
				{
					buf.append(tab + "Direct Reference: " + ext.getDirectReference().getId() + nl);
				}
				if (ext.getIndirectReference() != null)
				{
					buf.append(tab + "Indirect Reference: " + ext.getIndirectReference().ToString() + nl);
				}
				if (ext.getDataValueDescriptor() != null)
				{
					_dumpAsString(tab, verbose, ext.getDataValueDescriptor(), buf);
				}
				buf.append(tab + "Encoding: " + ext.getEncoding() + nl);
				_dumpAsString(tab, verbose, ext.getExternalContent(), buf);
			}
			else
			{
				buf.append(indent + obj.ToString() + nl);
			}
		}

		private static string outputApplicationSpecific(string type, string indent, bool verbose, ASN1Primitive obj, string nl)
		{
			ASN1ApplicationSpecific app = ASN1ApplicationSpecific.getInstance(obj);
			StringBuffer buf = new StringBuffer();

			if (app.isConstructed())
			{
				try
				{
					ASN1Sequence s = ASN1Sequence.getInstance(app.getObject(BERTags_Fields.SEQUENCE));
					buf.append(indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "]" + nl);
					for (Enumeration e = s.getObjects(); e.hasMoreElements();)
					{
						_dumpAsString(indent + TAB, verbose, (ASN1Primitive)e.nextElement(), buf);
					}
				}
				catch (IOException e)
				{
					buf.append(e);
				}
				return buf.ToString();
			}

			return indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "] (" + Strings.fromByteArray(Hex.encode(app.getContents())) + ")" + nl;
		}

		/// <summary>
		/// dump out a DER object as a formatted string, in non-verbose mode.
		/// </summary>
		/// <param name="obj"> the ASN1Primitive to be dumped out. </param>
		/// <returns>  the resulting string. </returns>
		public static string dumpAsString(object obj)
		{
			return dumpAsString(obj, false);
		}

		/// <summary>
		/// Dump out the object as a string.
		/// </summary>
		/// <param name="obj">  the object to be dumped </param>
		/// <param name="verbose">  if true, dump out the contents of octet and bit strings. </param>
		/// <returns>  the resulting string. </returns>
		public static string dumpAsString(object obj, bool verbose)
		{
			StringBuffer buf = new StringBuffer();

			if (obj is ASN1Primitive)
			{
				_dumpAsString("", verbose, (ASN1Primitive)obj, buf);
			}
			else if (obj is ASN1Encodable)
			{
				_dumpAsString("", verbose, ((ASN1Encodable)obj).toASN1Primitive(), buf);
			}
			else
			{
				return "unknown object type " + obj.ToString();
			}

			return buf.ToString();
		}

		private static string dumpBinaryDataAsString(string indent, byte[] bytes)
		{
			string nl = Strings.lineSeparator();
			StringBuffer buf = new StringBuffer();

			indent += TAB;

			buf.append(nl);
			for (int i = 0; i < bytes.Length; i += SAMPLE_SIZE)
			{
				if (bytes.Length - i > SAMPLE_SIZE)
				{
					buf.append(indent);
					buf.append(Strings.fromByteArray(Hex.encode(bytes, i, SAMPLE_SIZE)));
					buf.append(TAB);
					buf.append(calculateAscString(bytes, i, SAMPLE_SIZE));
					buf.append(nl);
				}
				else
				{
					buf.append(indent);
					buf.append(Strings.fromByteArray(Hex.encode(bytes, i, bytes.Length - i)));
					for (int j = bytes.Length - i; j != SAMPLE_SIZE; j++)
					{
						buf.append("  ");
					}
					buf.append(TAB);
					buf.append(calculateAscString(bytes, i, bytes.Length - i));
					buf.append(nl);
				}
			}

			return buf.ToString();
		}

		private static string calculateAscString(byte[] bytes, int off, int len)
		{
			StringBuffer buf = new StringBuffer();

			for (int i = off; i != off + len; i++)
			{
				if (bytes[i] >= (byte)' ' && bytes[i] <= (byte)'~')
				{
					buf.append((char)bytes[i]);
				}
			}

			return buf.ToString();
		}
	}

}