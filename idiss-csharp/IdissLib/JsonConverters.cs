using System;
using System.Text.Json;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace IdissLib
{

    /// A JsonConverter for JSON serialization and deserialization of objects of type Dictionary<AttributeTag, Attribute>
    // It is public so that in case be used in tests and from applications using the library.
    public class DictionaryConverter : JsonConverter<Dictionary<AttributeTag, Attribute>>
    {
        public override Dictionary<AttributeTag, Attribute> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException();
            }
            var value = new Dictionary<AttributeTag, Attribute>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    return value;
                }
                string keyString = reader.GetString();
                var key = new AttributeTag(keyString);
                reader.Read();
                string itemString = reader.GetString();
                var itemValue = new Attribute(itemString);
                value.Add(key, itemValue);
            }
            throw new JsonException("Error Occured");
        }

        public override void Write(Utf8JsonWriter writer, Dictionary<AttributeTag, Attribute> value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            foreach (KeyValuePair<AttributeTag, Attribute> item in value)
            {
                writer.WriteString(item.Key.tag, item.Value.attribute);
            }
            writer.WriteEndObject();
        }
    }

    /// A JsonConverter for JSON serialization and deserialization of objects of type YearMonth.
    public class YearMonthConverter : JsonConverter<YearMonth>
    {
        public override YearMonth Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string str = reader.GetString();
            return new YearMonth(str);
        }

        public override void Write(Utf8JsonWriter writer, YearMonth value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.str);
        }
    }


    /// A JsonConverter for JSON serialization and deserialization of objects of type AccountAddress.
    public class AccountAddressConverter : JsonConverter<AccountAddress>
    {
        public override AccountAddress Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string address = reader.GetString();
            return new AccountAddress(address);
        }

        public override void Write(Utf8JsonWriter writer, AccountAddress value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.address);
        }
    }
}