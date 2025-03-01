import { Field, InputType } from '@nestjs/graphql';
import { HashesInput, Dictionary } from '../../../../core/types/common-data-types';
import GraphQLJSON from 'graphql-type-json';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';
@InputType()
class NTFSFileExtensionInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  sid?: string;

  @Field(() => [AlternateDataStreamInput], { nullable: true })
  alternate_data_streams?: AlternateDataStreamInput[];
}

@InputType()
class AlternateDataStreamInput extends CyberObservableCommonInput{
  @Field(() => String)
  name: string;

  @Field(() =>HashesInput, { nullable: true })
  hashes?: HashesInput[];

  @Field(() => Number, { nullable: true })
  size?: number;
}

@InputType()
class UnixFileExtensionInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  group_id?: string;

  @Field(() => String, { nullable: true })
  user_id?: string;

  @Field(() => Number, { nullable: true })
  mode?: number;
}

@InputType()
class PDFFileExtensionInput extends CyberObservableCommonInput {
  @Field(() => Number, { nullable: true })
  version?: number;

  @Field(() => Boolean, { nullable: true })
  is_optimized?: boolean;

  @Field(() => GraphQLJSON, { nullable: true })
  document_info_dict?: Dictionary;

  @Field(() => String, { nullable: true })
  pdfid0?: string;

  @Field(() => String, { nullable: true })
  pdfid1?: string;
}

@InputType()
class RasterImageFileExtensionInput extends CyberObservableCommonInput {
  @Field(() => Number, { nullable: true })
  image_height?: number;

  @Field(() => Number, { nullable: true })
  image_width?: number;

  @Field(() => Number, { nullable: true })
  bits_per_pixel?: number;

  @Field(() => GraphQLJSON, { nullable: true })
  exif_tags?: Dictionary;
}

@InputType()
class WindowsPEBinaryFileExtensionInput extends CyberObservableCommonInput{
  @Field(() => String, { nullable: true })
  pe_type?: string;

  @Field(() => String, { nullable: true })
  imphash?: string;

  @Field(() => GraphQLJSON, { nullable: true })
  optional_header?: Dictionary;

  @Field(() => [WindowsPESectionInput], { nullable: true })
  sections?: WindowsPESectionInput[];
}

@InputType()
class WindowsPESectionInput extends CyberObservableCommonInput{
  @Field(() => String)
  name: string;

  @Field(() => Number, { nullable: true })
  size?: number;

  @Field(() => Number, { nullable: true })
  entropy?: number;

  @Field(() => HashesInput, { nullable: true })
  hashes?: HashesInput[];
}

@InputType()
export class CreateFileInput extends CyberObservableCommonInput {
  @Field(() => HashesInput, { nullable: true })
  hashes?: HashesInput[];

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

  @Field(() => [String], { nullable: true })
  contains_refs?: string[];

  @Field(() => String, { nullable: true })
  content_ref?: string;

  @Field(() => NTFSFileExtensionInput, { nullable: true })
  ntfs_ext?: NTFSFileExtensionInput;

  @Field(() => UnixFileExtensionInput, { nullable: true })
  unix_ext?: UnixFileExtensionInput;

  @Field(() => WindowsPEBinaryFileExtensionInput, { nullable: true })
  windows_pe_binary_ext?: WindowsPEBinaryFileExtensionInput;

  @Field(() => PDFFileExtensionInput, { nullable: true })
  pdf_ext?: PDFFileExtensionInput;

  @Field(() => RasterImageFileExtensionInput, { nullable: true })
  raster_image_ext?: RasterImageFileExtensionInput;
}

@InputType()
export class UpdateFileInput extends CreateFileInput {}