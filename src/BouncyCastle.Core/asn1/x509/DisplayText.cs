using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// <code>DisplayText</code> class, used in
	/// <code>CertificatePolicies</code> X509 V3 extensions (in policy qualifiers).
	/// 
	/// <para>It stores a string in a chosen encoding. 
	/// <pre>
	/// DisplayText ::= CHOICE {
	///      ia5String        IA5String      (SIZE (1..200)),
	///      visibleString    VisibleString  (SIZE (1..200)),
	///      bmpString        BMPString      (SIZE (1..200)),
	///      utf8String       UTF8String     (SIZE (1..200)) }
	/// </pre>
	/// </para>
	/// </summary>
	/// <seealso cref= PolicyQualifierInfo </seealso>
	/// <seealso cref= PolicyInformation </seealso>
	public class DisplayText : ASN1Object, ASN1Choice
	{
	   /// <summary>
	   /// Constant corresponding to ia5String encoding. 
	   /// 
	   /// </summary>
	   public const int CONTENT_TYPE_IA5STRING = 0;
	   /// <summary>
	   /// Constant corresponding to bmpString encoding. 
	   /// 
	   /// </summary>
	   public const int CONTENT_TYPE_BMPSTRING = 1;
	   /// <summary>
	   /// Constant corresponding to utf8String encoding. 
	   /// 
	   /// </summary>
	   public const int CONTENT_TYPE_UTF8STRING = 2;
	   /// <summary>
	   /// Constant corresponding to visibleString encoding. 
	   /// 
	   /// </summary>
	   public const int CONTENT_TYPE_VISIBLESTRING = 3;

	   /// <summary>
	   /// Describe constant <code>DISPLAY_TEXT_MAXIMUM_SIZE</code> here.
	   /// 
	   /// </summary>
	   public const int DISPLAY_TEXT_MAXIMUM_SIZE = 200;

	   internal int contentType;
	   internal ASN1String contents;

	   /// <summary>
	   /// Creates a new <code>DisplayText</code> instance.
	   /// </summary>
	   /// <param name="type"> the desired encoding type for the text. </param>
	   /// <param name="text"> the text to store. Strings longer than 200
	   /// characters are truncated.  </param>
	   public DisplayText(int type, string text)
	   {
		  if (text.Length > DISPLAY_TEXT_MAXIMUM_SIZE)
		  {
			 // RFC3280 limits these strings to 200 chars
			 // truncate the string
			 text = text.Substring(0, DISPLAY_TEXT_MAXIMUM_SIZE);
		  }

		  contentType = type;
		  switch (type)
		  {
			 case CONTENT_TYPE_IA5STRING:
				contents = new DERIA5String(text);
				break;
			 case CONTENT_TYPE_UTF8STRING:
				contents = new DERUTF8String(text);
				break;
			 case CONTENT_TYPE_VISIBLESTRING:
				contents = new DERVisibleString(text);
				break;
			 case CONTENT_TYPE_BMPSTRING:
				contents = new DERBMPString(text);
				break;
			 default:
				contents = new DERUTF8String(text);
				break;
		  }
	   }

	   /// <summary>
	   /// Creates a new <code>DisplayText</code> instance.
	   /// </summary>
	   /// <param name="text"> the text to encapsulate. Strings longer than 200
	   /// characters are truncated.  </param>
	   public DisplayText(string text)
	   {
		  // by default use UTF8String
		  if (text.Length > DISPLAY_TEXT_MAXIMUM_SIZE)
		  {
			 text = text.Substring(0, DISPLAY_TEXT_MAXIMUM_SIZE);
		  }

		  contentType = CONTENT_TYPE_UTF8STRING;
		  contents = new DERUTF8String(text);
	   }

	   /// <summary>
	   /// Creates a new <code>DisplayText</code> instance.
	   /// <para>Useful when reading back a <code>DisplayText</code> class
	   /// from it's ASN1Encodable/DEREncodable form. 
	   /// 
	   /// </para>
	   /// </summary>
	   /// <param name="de"> a <code>DEREncodable</code> instance.  </param>
	   private DisplayText(ASN1String de)
	   {
		  contents = de;
		  if (de is DERUTF8String)
		  {
			 contentType = CONTENT_TYPE_UTF8STRING;
		  }
		  else if (de is DERBMPString)
		  {
			 contentType = CONTENT_TYPE_BMPSTRING;
		  }
		  else if (de is DERIA5String)
		  {
			 contentType = CONTENT_TYPE_IA5STRING;
		  }
		  else if (de is DERVisibleString)
		  {
			 contentType = CONTENT_TYPE_VISIBLESTRING;
		  }
		  else
		  {
			 throw new IllegalArgumentException("unknown STRING type in DisplayText");
		  }
	   }

	   public static DisplayText getInstance(object obj)
	   {
		  if (obj is ASN1String)
		  {
			  return new DisplayText((ASN1String)obj);
		  }
		  else if (obj == null || obj is DisplayText)
		  {
			  return (DisplayText)obj;
		  }

		  throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
	   }

	   public static DisplayText getInstance(ASN1TaggedObject obj, bool @explicit)
	   {
		   return getInstance(obj.getObject()); // must be explicitly tagged
	   }

	   public override ASN1Primitive toASN1Primitive()
	   {
		  return (ASN1Primitive)contents;
	   }

	   /// <summary>
	   /// Returns the stored <code>String</code> object. 
	   /// </summary>
	   /// <returns> the stored text as a <code>String</code>.  </returns>
	   public virtual string getString()
	   {
		  return contents.getString();
	   }
	}

}