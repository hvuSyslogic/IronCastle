using org.bouncycastle.asn1;

namespace org.bouncycastle.asn1.eac
{

	public class EACTags
	{
		public const int COUNTRY_CODE_NATIONAL_DATA = 0x01;
		public const int ISSUER_IDENTIFICATION_NUMBER = 0x02; //0x42;
		public const int CARD_SERVICE_DATA = 0x03;
		public const int INITIAL_ACCESS_DATA = 0x04;
		public const int CARD_ISSUER_DATA = 0x05;
		public const int PRE_ISSUING_DATA = 0x06;
		public const int CARD_CAPABILITIES = 0x07;
		public const int STATUS_INFORMATION = 0x08;
		public const int EXTENDED_HEADER_LIST = 0x0D;
		public const int APPLICATION_IDENTIFIER = 0x0F;
		public const int APPLICATION_LABEL = 0x10;
		public const int FILE_REFERENCE = 0x11; // 0x51
		public const int COMMAND_TO_PERFORM = 0x12;
		public const int DISCRETIONARY_DATA = 0x13;
		public const int OFFSET_DATA_OBJECT = 0x14;
		public const int TRACK1_APPLICATION = 0x16;
		public const int TRACK2_APPLICATION = 0x17;
		public const int TRACK3_APPLICATION = 0x18;
		public const int CARD_EXPIRATION_DATA = 0x19;
		public const int PRIMARY_ACCOUNT_NUMBER = 0x1A; // PAN
		public const int NAME = 0x1B;
		public const int TAG_LIST = 0x1C;
		public const int HEADER_LIST = 0x1D;
		public const int LOGIN_DATA = 0x1E;
		public const int CARDHOLDER_NAME = 0x20; // 0x5F20;
		public const int TRACK1_CARD = 0x21;
		public const int TRACK2_CARD = 0x22;
		public const int TRACK3_CARD = 0x23;
		public const int APPLICATION_EXPIRATION_DATE = 0x24; // 0x5F24;
		public const int APPLICATION_EFFECTIVE_DATE = 0x25; // 0x5F25;
		public const int CARD_EFFECTIVE_DATE = 0x26;
		public const int INTERCHANGE_CONTROL = 0x27;
		public const int COUNTRY_CODE = 0x28;
		public const int INTERCHANGE_PROFILE = 0x29; // 0x5F29;
		public const int CURRENCY_CODE = 0x2A;
		public const int DATE_OF_BIRTH = 0x2B;
		public const int CARDHOLDER_NATIONALITY = 0x2C;
		public const int LANGUAGE_PREFERENCES = 0x2D;
		public const int CARDHOLDER_BIOMETRIC_DATA = 0x2E;
		public const int PIN_USAGE_POLICY = 0x2F;
		public const int SERVICE_CODE = 0x30;
		public const int TRANSACTION_COUNTER = 0x32;
		public const int TRANSACTION_DATE = 0x33;
		public const int CARD_SEQUENCE_NUMBER = 0x34;
		public const int SEX = 0x35;
		public const int CURRENCY_EXPONENT = 0x36;
		public const int STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP = 0x37; // 0x5F37;
		public const int SIGNATURE = 0x37; // 0x5F37
		public const int STATIC_INTERNAL_AUTHENTIFICATION_FIRST_DATA = 0x38; // 0x5F38
		public const int STATIC_INTERNAL_AUTHENTIFICATION_SECOND_DATA = 0x39; // 0x5F39
		public const int DYNAMIC_INTERNAL_AUTHENTIFICATION = 0x3A; // 0x5F3A
		public const int DYNAMIC_EXTERNAL_AUTHENTIFICATION = 0x3B; // 0x5F3B
		public const int DYNAMIC_MUTUAL_AUTHENTIFICATION = 0x3C; // 0x5F3C
		public const int CARDHOLDER_PORTRAIT_IMAGE = 0x40; // 0x5F40
		public const int ELEMENT_LIST = 0x41; // 0x5F41
		public const int ADDRESS = 0x42; // 0x5F42
		public const int CARDHOLDER_HANDWRITTEN_SIGNATURE = 0x43; // 0x5F43
		public const int APPLICATION_IMAGE = 0x44; // 0x5F44
		public const int DISPLAY_IMAGE = 0x45; // 0x5F45
		public const int TIMER = 0x46; // 0x5F46
		public const int MESSAGE_REFERENCE = 0x47; // 0x5F47
		public const int CARDHOLDER_PRIVATE_KEY = 0x48; // 0x5F48
		public const int CARDHOLDER_PUBLIC_KEY = 0x49; // 0x5F49
		public const int CERTIFICATION_AUTHORITY_PUBLIC_KEY = 0x4A; // 0x5F4A
		public const int DEPRECATED = 0x4B; // 0x5F4B
		public const int CERTIFICATE_HOLDER_AUTHORIZATION = 0x4C; // 0x5F4C Not yet defined in iso7816. The allocation is requested
		public const int INTEGRATED_CIRCUIT_MANUFACTURER_ID = 0x4D; // 0x5F4D
		public const int CERTIFICATE_CONTENT = 0x4E; // 0x5F4E
		public const int UNIFORM_RESOURCE_LOCATOR = 0x50; // 0x5F50
		public const int ANSWER_TO_RESET = 0x51; // 0x5F51
		public const int HISTORICAL_BYTES = 0x52; // 0x5F52
		public const int DIGITAL_SIGNATURE = 0x3D; // 0x5F3D
		public const int APPLICATION_TEMPLATE = 0x01; // 0x61
		public const int FCP_TEMPLATE = 0x02; // 0x62
		public const int WRAPPER = 0x03; // 0x63
		public const int FMD_TEMPLATE = 0x04; // 0x64
		public const int CARDHOLDER_RELATIVE_DATA = 0x05; // 0x65
		public const int CARD_DATA = 0x06; // 0x66
		public const int AUTHENTIFICATION_DATA = 0x07; // 0x67
		public const int SPECIAL_USER_REQUIREMENTS = 0x08; // 0x68
		public const int LOGIN_TEMPLATE = 0x0A; // 0x6A
		public const int QUALIFIED_NAME = 0x0B; // 0x6B
		public const int CARDHOLDER_IMAGE_TEMPLATE = 0x0C; // 0x6C
		public const int APPLICATION_IMAGE_TEMPLATE = 0x0D; // 0x6D
		public const int APPLICATION_RELATED_DATA = 0x0E; // 0x6E
		public const int FCI_TEMPLATE = 0x0F; // 0x6F
		public const int DISCRETIONARY_DATA_OBJECTS = 0x13; // 0x73
		public const int COMPATIBLE_TAG_ALLOCATION_AUTHORITY = 0x18; // 0x78
		public const int COEXISTANT_TAG_ALLOCATION_AUTHORITY = 0x19; // 0x79
		public const int SECURITY_SUPPORT_TEMPLATE = 0x1A; // 0x7A
		public const int SECURITY_ENVIRONMENT_TEMPLATE = 0x1B; // 0x7B
		public const int DYNAMIC_AUTHENTIFICATION_TEMPLATE = 0x1C; // 0x7C
		public const int SECURE_MESSAGING_TEMPLATE = 0x1D; // 0x7D
		public const int NON_INTERINDUSTRY_DATA_OBJECT_NESTING_TEMPLATE = 0x1E; // 0x7E
		public const int DISPLAY_CONTROL = 0x20; // 0x7F20
		public const int CARDHOLDER_CERTIFICATE = 0x21; // 0x7F21;
		public const int CV_CERTIFICATE = 0x21; // 0x7F21;
		public const int CARDHOLER_REQUIREMENTS_INCLUDED_FEATURES = 0x22; // 0x7F22;
		public const int CARDHOLER_REQUIREMENTS_EXCLUDED_FEATURES = 0x23; // 0x7F23;
		public const int BIOMETRIC_DATA_TEMPLATE = 0x2E; // 0x7F2E;
		public const int DIGITAL_SIGNATURE_BLOCK = 0x3D; // 0x7F3D;
		public const int CARDHOLDER_PRIVATE_KEY_TEMPLATE = 0x48; // 0x7F48;
		public const int CARDHOLDER_PUBLIC_KEY_TEMPLATE = 0x49; // 0x7F49;
		public const int CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE = 0x4C; // 0x7F4C;
		public const int CERTIFICATE_CONTENT_TEMPLATE = 0x4E; // 0x7F4E;
		public const int CERTIFICATE_BODY = 0x4E; // 0x7F4E;
		public const int BIOMETRIC_INFORMATION_TEMPLATE = 0x00; // 0x60
		public const int BIOMETRIC_INFORMATION_GROUP_TEMPLATE = 0x01; // 0x61

		public static int getTag(int encodedTag)
		{
			/*
			int i;
			for (i = 24; i>=0; i-=8) {
			    if (((0xFF<<i) & tag) != 0)
			        return (((0xFF<<i) & tag) >> i);
			}
			return 0;
			*/
			return decodeTag(encodedTag);
		}

		public static int getTagNo(int tag)
		{
			int i;
			for (i = 24; i >= 0; i -= 8)
			{
				if (((0xFF << i) & tag) != 0)
				{
					return ((~(0xFF << i)) & tag);
				}
			}
			return 0;
		}

		public static int encodeTag(ASN1ApplicationSpecific spec)
		{
			int retValue = BERTags_Fields.APPLICATION;
			bool constructed = spec.isConstructed();
			if (constructed)
			{
				retValue |= BERTags_Fields.CONSTRUCTED;
			}

			int tag = spec.getApplicationTag();

			if (tag > 31)
			{
				retValue |= 0x1F;
				retValue <<= 8;

				int currentByte = tag & 0x7F;
				retValue |= currentByte;
				tag >>= 7;

				while (tag > 0)
				{
					retValue |= 0x80;
					retValue <<= 8;

					currentByte = tag & 0x7F;
					retValue |= currentByte;
					tag >>= 7;
				}
			}
			else
			{
				retValue |= tag;
			}

			return retValue;
		}

		public static int decodeTag(int tag)
		{
			int retValue = 0;
			bool multiBytes = false;
			for (int i = 24; i >= 0; i -= 8)
			{
				int currentByte = tag >> i & 0xFF;
				if (currentByte == 0)
				{
					continue;
				}

				if (multiBytes)
				{
					retValue <<= 7;
					retValue |= currentByte & 0x7F;
				}
				else if ((currentByte & 0x1F) == 0x1F)
				{
					multiBytes = true;
				}
				else
				{
					return currentByte & 0x1F; // higher order bit are for DER.Constructed and type
				}
			}
			return retValue;
		}
	}

}