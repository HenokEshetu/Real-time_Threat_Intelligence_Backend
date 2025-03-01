import { Field, ObjectType } from '@nestjs/graphql';
import GraphQLJSON from 'graphql-type-json';
import { CyberObservableCommonProperties, Hashes, Dictionary } from '../../../../core/types/common-data-types';

@ObjectType()
class NTFSFileExtension {
  @Field(() => String, { nullable: true })
  sid?: string;

  @Field(() => [String], { nullable: true })
  alternate_data_streams?: {
    name: string;
    hashes?: Hashes[];
    size?: number;
  }[];
}

@ObjectType()
class UnixFileExtension {
  @Field(() => String, { nullable: true })
  group_id?: string;

  @Field(() => String, { nullable: true })
  user_id?: string;

  @Field(() => Number, { nullable: true })
  mode?: number;
}

@ObjectType()
class PDFFileExtension {
  @Field(() => Number, { nullable: true })
  version?: number;

  @Field(() => Number, { nullable: true })
  is_optimized?: boolean;

  @Field(() => String, { nullable: true })
  document_info_dict?: Dictionary;

  @Field(() => Number, { nullable: true })
  pdfid0?: string;

  @Field(() => Number, { nullable: true })
  pdfid1?: string;
}

@ObjectType()
class RasterImageFileExtension {
  @Field(() => Number, { nullable: true })
  image_height?: number;

  @Field(() => Number, { nullable: true })
  image_width?: number;

  @Field(() => Number, { nullable: true })
  bits_per_pixel?: number;

  @Field(() => [String], { nullable: true })
  exif_tags?: Dictionary;
}

@ObjectType()
class WindowsPEBinaryFileExtension {
  @Field(() => String, { nullable: true })
  pe_type?: string;

  @Field(() => String, { nullable: true })
  imphash?: string;

  @Field(() => GraphQLJSON,  { nullable: true })
  optional_header?: Dictionary;

  @Field(() => [GraphQLJSON], { nullable: true })
  sections?: Dictionary[];
}

@ObjectType()
class WindowsPESection {
  @Field(() => String)
  name: string;

  @Field(() => Number, { nullable: true })
  size?: number;

  @Field(() => Number, { nullable: true })
  entropy?: number;

  @Field(() => Hashes, { nullable: true })
  hashes?: Hashes[];
}


@ObjectType()
export class File extends CyberObservableCommonProperties {
  @Field(() => Hashes, { nullable: true })
  
  hashes?: Hashes[];

  @Field(() => Number, { nullable: true })
  
  size?: number;

  @Field(() => String, { nullable: true })
 
  name?: string;

  @Field(() => String, { nullable: true })
  
  name_enc?: string;

  @Field(() => String, { nullable: true })
  
  magic_number_hex?: string;

  @Field(() => String, { nullable: true })
 
  mime_type?: string;

  @Field(() => Date, { nullable: true })
  
  ctime?: Date;

  @Field(() => Date, { nullable: true })
  
  mtime?: Date;

  @Field(() => Date, { nullable: true })

  atime?: Date;

  @Field(() => [String], { nullable: true })
  
  parent_directory_ref?: string[];

  @Field(() => Boolean, { nullable: true })
  
  contains_refs?: string[];

  @Field(() => String, { nullable: true })
  
  content_ref?: string;

  @Field(() => NTFSFileExtension, { nullable: true })
 
  ntfs_ext?: NTFSFileExtension;

  @Field(() => UnixFileExtension, { nullable: true })
 
  unix_ext?: UnixFileExtension;

  @Field(() => WindowsPEBinaryFileExtension, { nullable: true })
  
  windows_pe_binary_ext?: WindowsPEBinaryFileExtension;

  @Field(() => PDFFileExtension, { nullable: true })
  
  pdf_ext?: PDFFileExtension;

  @Field(() => RasterImageFileExtension, { nullable: true })
 
  raster_image_ext?: RasterImageFileExtension;
}