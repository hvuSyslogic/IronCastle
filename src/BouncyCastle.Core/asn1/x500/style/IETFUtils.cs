using org.bouncycastle.asn1;

using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.asn1.x500.style
{

		
	public class IETFUtils
	{
		private static string unescape(string elt)
		{
			if (elt.Length == 0 || (elt.IndexOf('\\') < 0 && elt.IndexOf('"') < 0))
			{
				return elt.Trim();
			}

			char[] elts = elt.ToCharArray();
			bool escaped = false;
			bool quoted = false;
			StringBuffer buf = new StringBuffer(elt.Length);
			int start = 0;

			// if it's an escaped hash string and not an actual encoding in string form
			// we need to leave it escaped.
			if (elts[0] == '\\')
			{
				if (elts[1] == '#')
				{
					start = 2;
					buf.append(@"\#");
				}
			}

			bool nonWhiteSpaceEncountered = false;
			int lastEscaped = 0;
			char hex1 = (char)0;

			for (int i = start; i != elts.Length; i++)
			{
				char c = elts[i];

				if (c != ' ')
				{
					nonWhiteSpaceEncountered = true;
				}

				if (c == '"')
				{
					if (!escaped)
					{
						quoted = !quoted;
					}
					else
					{
						buf.append(c);
					}
					escaped = false;
				}
				else if (c == '\\' && !(escaped || quoted))
				{
					escaped = true;
					lastEscaped = buf.length();
				}
				else
				{
					if (c == ' ' && !escaped && !nonWhiteSpaceEncountered)
					{
						continue;
					}
					if (escaped && isHexDigit(c))
					{
						if (hex1 != (char)0)
						{
							buf.append((char)(convertHex(hex1) * 16 + convertHex(c)));
							escaped = false;
							hex1 = (char)0;
							continue;
						}
						hex1 = c;
						continue;
					}
					buf.append(c);
					escaped = false;
				}
			}

			if (buf.length() > 0)
			{
				while (buf.charAt(buf.length() - 1) == ' ' && lastEscaped != (buf.length() - 1))
				{
					buf.setLength(buf.length() - 1);
				}
			}

			return buf.ToString();
		}

		private static bool isHexDigit(char c)
		{
			return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
		}

		private static int convertHex(char c)
		{
			if ('0' <= c && c <= '9')
			{
				return c - '0';
			}
			if ('a' <= c && c <= 'f')
			{
				return c - 'a' + 10;
			}
			return c - 'A' + 10;
		}

		public static RDN[] rDNsFromString(string name, X500NameStyle x500Style)
		{
			X500NameTokenizer nTok = new X500NameTokenizer(name);
			X500NameBuilder builder = new X500NameBuilder(x500Style);

			while (nTok.hasMoreTokens())
			{
				string token = nTok.nextToken();

				if (token.IndexOf('+') > 0)
				{
					X500NameTokenizer pTok = new X500NameTokenizer(token, '+');
					X500NameTokenizer vTok = new X500NameTokenizer(pTok.nextToken(), '=');

					string attr = vTok.nextToken();

					if (!vTok.hasMoreTokens())
					{
						throw new IllegalArgumentException("badly formatted directory string");
					}

					string value = vTok.nextToken();
					ASN1ObjectIdentifier oid = x500Style.attrNameToOID(attr.Trim());

					if (pTok.hasMoreTokens())
					{
						Vector oids = new Vector();
						Vector values = new Vector();

						oids.addElement(oid);
						values.addElement(unescape(value));

						while (pTok.hasMoreTokens())
						{
							vTok = new X500NameTokenizer(pTok.nextToken(), '=');

							attr = vTok.nextToken();

							if (!vTok.hasMoreTokens())
							{
								throw new IllegalArgumentException("badly formatted directory string");
							}

							value = vTok.nextToken();
							oid = x500Style.attrNameToOID(attr.Trim());


							oids.addElement(oid);
							values.addElement(unescape(value));
						}

						builder.addMultiValuedRDN(toOIDArray(oids), toValueArray(values));
					}
					else
					{
						builder.addRDN(oid, unescape(value));
					}
				}
				else
				{
					X500NameTokenizer vTok = new X500NameTokenizer(token, '=');

					string attr = vTok.nextToken();

					if (!vTok.hasMoreTokens())
					{
						throw new IllegalArgumentException("badly formatted directory string");
					}

					string value = vTok.nextToken();
					ASN1ObjectIdentifier oid = x500Style.attrNameToOID(attr.Trim());

					builder.addRDN(oid, unescape(value));
				}
			}

			return builder.build().getRDNs();
		}

		private static string[] toValueArray(Vector values)
		{
			string[] tmp = new string[values.size()];

			for (int i = 0; i != tmp.Length; i++)
			{
				tmp[i] = (string)values.elementAt(i);
			}

			return tmp;
		}

		private static ASN1ObjectIdentifier[] toOIDArray(Vector oids)
		{
			ASN1ObjectIdentifier[] tmp = new ASN1ObjectIdentifier[oids.size()];

			for (int i = 0; i != tmp.Length; i++)
			{
				tmp[i] = (ASN1ObjectIdentifier)oids.elementAt(i);
			}

			return tmp;
		}

		public static string[] findAttrNamesForOID(ASN1ObjectIdentifier oid, Hashtable lookup)
		{
			int count = 0;
			for (Enumeration en = lookup.elements(); en.hasMoreElements();)
			{
				if (oid.Equals(en.nextElement()))
				{
					count++;
				}
			}

			string[] aliases = new string[count];
			count = 0;

			for (Enumeration en = lookup.keys(); en.hasMoreElements();)
			{
				string key = (string)en.nextElement();
				if (oid.Equals(lookup.get(key)))
				{
					aliases[count++] = key;
				}
			}

			return aliases;
		}

		public static ASN1ObjectIdentifier decodeAttrName(string name, Hashtable lookUp)
		{
			if (Strings.toUpperCase(name).StartsWith("OID.", StringComparison.Ordinal))
			{
				return new ASN1ObjectIdentifier(name.Substring(4));
			}
			else if (name[0] >= '0' && name[0] <= '9')
			{
				return new ASN1ObjectIdentifier(name);
			}

			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)lookUp.get(Strings.toLowerCase(name));
			if (oid == null)
			{
				throw new IllegalArgumentException("Unknown object id - " + name + " - passed to distinguished name");
			}

			return oid;
		}

		public static ASN1Encodable valueFromHexString(string str, int off)
		{
			byte[] data = new byte[(str.Length - off) / 2];
			for (int index = 0; index != data.Length; index++)
			{
				char left = str[(index * 2) + off];
				char right = str[(index * 2) + off + 1];

				data[index] = (byte)((convertHex(left) << 4) | convertHex(right));
			}

			return ASN1Primitive.fromByteArray(data);
		}

		public static void appendRDN(StringBuffer buf, RDN rdn, Hashtable oidSymbols)
		{
			if (rdn.isMultiValued())
			{
				AttributeTypeAndValue[] atv = rdn.getTypesAndValues();
				bool firstAtv = true;

				for (int j = 0; j != atv.Length; j++)
				{
					if (firstAtv)
					{
						firstAtv = false;
					}
					else
					{
						buf.append('+');
					}

					IETFUtils.appendTypeAndValue(buf, atv[j], oidSymbols);
				}
			}
			else
			{
				if (rdn.getFirst() != null)
				{
					IETFUtils.appendTypeAndValue(buf, rdn.getFirst(), oidSymbols);
				}
			}
		}

		public static void appendTypeAndValue(StringBuffer buf, AttributeTypeAndValue typeAndValue, Hashtable oidSymbols)
		{
			string sym = (string)oidSymbols.get(typeAndValue.getType());

			if (!string.ReferenceEquals(sym, null))
			{
				buf.append(sym);
			}
			else
			{
				buf.append(typeAndValue.getType().getId());
			}

			buf.append('=');

			buf.append(valueToString(typeAndValue.getValue()));
		}

		public static string valueToString(ASN1Encodable value)
		{
			StringBuffer vBuf = new StringBuffer();

			if (value is ASN1String && !(value is DERUniversalString))
			{
				string v = ((ASN1String)value).getString();
				if (v.Length > 0 && v[0] == '#')
				{
					vBuf.append(@"\" + v);
				}
				else
				{
					vBuf.append(v);
				}
			}
			else
			{
				try
				{
					vBuf.append("#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER))));
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("Other value has no encoded form");
				}
			}

			int end = vBuf.length();
			int index = 0;

			if (vBuf.length() >= 2 && vBuf.charAt(0) == '\\' && vBuf.charAt(1) == '#')
			{
				index += 2;
			}

			while (index != end)
			{
				if ((vBuf.charAt(index) == ',') || (vBuf.charAt(index) == '"') || (vBuf.charAt(index) == '\\') || (vBuf.charAt(index) == '+') || (vBuf.charAt(index) == '=') || (vBuf.charAt(index) == '<') || (vBuf.charAt(index) == '>') || (vBuf.charAt(index) == ';'))
				{
					vBuf.insert(index, @"\");
					index++;
					end++;
				}

				index++;
			}

			int start = 0;
			if (vBuf.length() > 0)
			{
				while (vBuf.length() > start && vBuf.charAt(start) == ' ')
				{
					vBuf.insert(start, @"\");
					start += 2;
				}
			}

			int endBuf = vBuf.length() - 1;

			while (endBuf >= 0 && vBuf.charAt(endBuf) == ' ')
			{
				vBuf.insert(endBuf, '\\');
				endBuf--;
			}

			return vBuf.ToString();
		}

		private static string bytesToString(byte[] data)
		{
			char[] cs = new char[data.Length];

			for (int i = 0; i != cs.Length; i++)
			{
				cs[i] = (char)(data[i] & 0xff);
			}

			return new string(cs);
		}

		public static string canonicalize(string s)
		{
			string value = Strings.toLowerCase(s);

			if (value.Length > 0 && value[0] == '#')
			{
				ASN1Primitive obj = decodeObject(value);

				if (obj is ASN1String)
				{
					value = Strings.toLowerCase(((ASN1String)obj).getString());
				}
			}

			if (value.Length > 1)
			{
				int start = 0;
				while (start + 1 < value.Length && value[start] == '\\' && value[start + 1] == ' ')
				{
					start += 2;
				}

				int end = value.Length - 1;
				while (end - 1 > 0 && value[end - 1] == '\\' && value[end] == ' ')
				{
					end -= 2;
				}

				if (start > 0 || end < value.Length - 1)
				{
					value = value.Substring(start, (end + 1) - start);
				}
			}

			value = stripInternalSpaces(value);

			return value;
		}

		private static ASN1Primitive decodeObject(string oValue)
		{
			try
			{
				return ASN1Primitive.fromByteArray(Hex.decode(oValue.Substring(1)));
			}
			catch (IOException e)
			{
				throw new IllegalStateException("unknown encoding in name: " + e);
			}
		}

		public static string stripInternalSpaces(string str)
		{
			StringBuffer res = new StringBuffer();

			if (str.Length != 0)
			{
				char c1 = str[0];

				res.append(c1);

				for (int k = 1; k < str.Length; k++)
				{
					char c2 = str[k];
					if (!(c1 == ' ' && c2 == ' '))
					{
						res.append(c2);
					}
					c1 = c2;
				}
			}

			return res.ToString();
		}

		public static bool rDNAreEqual(RDN rdn1, RDN rdn2)
		{
			if (rdn1.isMultiValued())
			{
				if (rdn2.isMultiValued())
				{
					AttributeTypeAndValue[] atvs1 = rdn1.getTypesAndValues();
					AttributeTypeAndValue[] atvs2 = rdn2.getTypesAndValues();

					if (atvs1.Length != atvs2.Length)
					{
						return false;
					}

					for (int i = 0; i != atvs1.Length; i++)
					{
						if (!atvAreEqual(atvs1[i], atvs2[i]))
						{
							return false;
						}
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				if (!rdn2.isMultiValued())
				{
					return atvAreEqual(rdn1.getFirst(), rdn2.getFirst());
				}
				else
				{
					return false;
				}
			}

			return true;
		}

		private static bool atvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2)
		{
			if (atv1 == atv2)
			{
				return true;
			}

			if (atv1 == null)
			{
				return false;
			}

			if (atv2 == null)
			{
				return false;
			}

			ASN1ObjectIdentifier o1 = atv1.getType();
			ASN1ObjectIdentifier o2 = atv2.getType();

			if (!o1.Equals(o2))
			{
				return false;
			}

			string v1 = IETFUtils.canonicalize(IETFUtils.valueToString(atv1.getValue()));
			string v2 = IETFUtils.canonicalize(IETFUtils.valueToString(atv2.getValue()));

			if (!v1.Equals(v2))
			{
				return false;
			}

			return true;
		}
	}

}