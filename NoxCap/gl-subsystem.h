/******************************************************************************
    Copyright (C) 2013 by Hugh Bailey <obs.jim@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
******************************************************************************/

#pragma once
#include <stdint.h>

struct gl_platform;
struct gl_windowinfo;

enum copy_type { COPY_TYPE_ARB, COPY_TYPE_NV, COPY_TYPE_FBO_BLIT };


#define GS_MAX_TEXTURES 8


typedef struct gs_shader gs_shader_t;
typedef struct gs_device gs_device_t;
typedef struct gs_sampler_state gs_samplerstate_t;
typedef struct gs_texture gs_texture_t;
typedef struct gs_zstencil_buffer gs_zstencil_t;
typedef struct gs_vertex_buffer gs_vertbuffer_t;
typedef struct gs_index_buffer gs_indexbuffer_t;
typedef struct gs_swap_chain gs_swapchain_t;


typedef unsigned int GLuint;
typedef int GLint;
typedef unsigned int GLenum;



enum gs_texture_type {
	GS_TEXTURE_2D,
	GS_TEXTURE_3D,
	GS_TEXTURE_CUBE,
};


enum attrib_type {
	ATTRIB_POSITION,
	ATTRIB_NORMAL,
	ATTRIB_TANGENT,
	ATTRIB_COLOR,
	ATTRIB_TEXCOORD,
	ATTRIB_TARGET
};

struct shader_attrib {
	char *name;
	size_t index;
	enum attrib_type type;
};


#define DARRAY_INVALID ((size_t)-1)
#define DARRAY(type)                     \
	union {                          \
		struct darray da;        \
		struct {                 \
			type *array;     \
			size_t num;      \
			size_t capacity; \
		};                       \
	}

struct darray {
	void *array;
	size_t num;
	size_t capacity;
};

struct gs_sampler_state {
	gs_device_t *device;
	volatile long ref;

	GLint min_filter;
	GLint mag_filter;
	GLint address_u;
	GLint address_v;
	GLint address_w;
	GLint max_anisotropy;
};


struct gs_shader {
	gs_device_t *device;
	enum gs_shader_type type;
	GLuint obj;

	struct gs_shader_param *viewproj;
	struct gs_shader_param *world;

	DARRAY(struct shader_attrib) attribs;
	DARRAY(struct gs_shader_param) params;
	DARRAY(gs_samplerstate_t *) samplers;
};

enum gs_shader_param_type {
	GS_SHADER_PARAM_UNKNOWN,
	GS_SHADER_PARAM_BOOL,
	GS_SHADER_PARAM_FLOAT,
	GS_SHADER_PARAM_INT,
	GS_SHADER_PARAM_STRING,
	GS_SHADER_PARAM_VEC2,
	GS_SHADER_PARAM_VEC3,
	GS_SHADER_PARAM_VEC4,
	GS_SHADER_PARAM_INT2,
	GS_SHADER_PARAM_INT3,
	GS_SHADER_PARAM_INT4,
	GS_SHADER_PARAM_MATRIX4X4,
	GS_SHADER_PARAM_TEXTURE,
};

struct gs_shader_param {
	enum gs_shader_param_type type;

	char *name;
	gs_shader_t *shader;
	gs_samplerstate_t *next_sampler;
	GLint texture_id;
	size_t sampler_id;
	int array_count;

	struct gs_texture *texture;

	DARRAY(unsigned char) cur_value;
	DARRAY(unsigned char) def_value;
	BOOL changed;
};

struct program_param {
	GLint obj;
	struct gs_shader_param *param;
};

struct gs_program {
	gs_device_t *device;
	GLuint obj;
	struct gs_shader *vertex_shader;
	struct gs_shader *pixel_shader;

	DARRAY(struct program_param) params;
	DARRAY(GLint) attribs;

	struct gs_program **prev_next;
	struct gs_program *next;
};

extern struct gs_program *gs_program_create(struct gs_device *device);
extern void gs_program_destroy(struct gs_program *program);
extern void program_update_params(struct gs_program *shader);

struct gs_vertex_buffer {
	GLuint vao;
	GLuint vertex_buffer;
	GLuint normal_buffer;
	GLuint tangent_buffer;
	GLuint color_buffer;
	DARRAY(GLuint) uv_buffers;
	DARRAY(size_t) uv_sizes;

	gs_device_t *device;
	size_t num;
	BOOL dynamic;
	struct gs_vb_data *data;
};

extern BOOL load_vb_buffers(struct gs_program *program,
			    struct gs_vertex_buffer *vb,
			    struct gs_index_buffer *ib);

struct gs_index_buffer {
	GLuint buffer;
	enum gs_index_type type;
	GLuint gl_type;

	gs_device_t *device;
	void *data;
	size_t num;
	size_t width;
	size_t size;
	BOOL dynamic;
};

struct gs_texture {
	gs_device_t *device;
	enum gs_texture_type type;
	enum gs_color_format format;
	GLenum gl_format;
	GLenum gl_target;
	GLenum gl_internal_format;
	GLenum gl_type;
	GLuint texture;
	uint32_t levels;
	BOOL is_dynamic;
	BOOL is_render_target;
	BOOL is_dummy;
	BOOL gen_mipmaps;

	gs_samplerstate_t *cur_sampler;
	struct fbo_info *fbo;
};

struct gs_texture_2d {
	struct gs_texture base;

	uint32_t width;
	uint32_t height;
	BOOL gen_mipmaps;
	GLuint unpack_buffer;
};

struct gs_texture_cube {
	struct gs_texture base;

	uint32_t size;
};

struct gs_stage_surface {
	gs_device_t *device;

	enum gs_color_format format;
	uint32_t width;
	uint32_t height;

	uint32_t bytes_per_pixel;
	GLenum gl_format;
	GLint gl_internal_format;
	GLenum gl_type;
	GLuint pack_buffer;
};

struct gs_zstencil_buffer {
	gs_device_t *device;
	GLuint buffer;
	GLuint attachment;
	GLenum format;
};

struct fbo_info {
	GLuint fbo;
	uint32_t width;
	uint32_t height;
	enum gs_color_format format;

	gs_texture_t *cur_render_target;
	int cur_render_side;
	gs_zstencil_t *cur_zstencil_buffer;
};

struct gs_window {
#if defined(_WIN32)
	void *hwnd;
#elif defined(__APPLE__)
	__unsafe_unretained id view;
#elif defined(__linux__) || defined(__FreeBSD__)
	/* I'm not sure how portable defining id to uint32_t is. */
	uint32_t id;
	void *display;
#endif
};

enum gs_color_format {
	GS_UNKNOWN,
	GS_A8,
	GS_R8,
	GS_RGBA,
	GS_BGRX,
	GS_BGRA,
	GS_R10G10B10A2,
	GS_RGBA16,
	GS_R16,
	GS_RGBA16F,
	GS_RGBA32F,
	GS_RG16F,
	GS_RG32F,
	GS_R16F,
	GS_R32F,
	GS_DXT1,
	GS_DXT3,
	GS_DXT5,
	GS_R8G8,
};

enum gs_zstencil_format {
	GS_ZS_NONE,
	GS_Z16,
	GS_Z24_S8,
	GS_Z32F,
	GS_Z32F_S8X24,
};


struct gs_init_data {
	struct gs_window window;
	uint32_t cx, cy;
	uint32_t num_backbuffers;
	enum gs_color_format format;
	enum gs_zstencil_format zsformat;
	uint32_t adapter;
};

struct gs_swap_chain {
	gs_device_t *device;
	struct gl_windowinfo *wi;
	struct gs_init_data info;
};
struct gs_rect {
	int x;
	int y;
	int cx;
	int cy;
};

typedef union __declspec(intrin_type) __declspec(align(16)) __m128 {
	float               m128_f32[4];
	unsigned __int64    m128_u64[2];
	__int8              m128_i8[16];
	__int16             m128_i16[8];
	__int32             m128_i32[4];
	__int64             m128_i64[2];
	unsigned __int8     m128_u8[16];
	unsigned __int16    m128_u16[8];
	unsigned __int32    m128_u32[4];
} __m128;

struct vec4 {
	union {
		struct {
			float x, y, z, w;
		};
		float ptr[4];
		__m128 m;
	};
};

struct matrix4 {
	struct vec4 x, y, z, t;
};

struct gs_device {
	struct gl_platform *plat;
	enum copy_type copy_type;

	GLuint empty_vao;

	gs_texture_t *cur_render_target;
	gs_zstencil_t *cur_zstencil_buffer;
	int cur_render_side;
	gs_texture_t *cur_textures[GS_MAX_TEXTURES];
	gs_samplerstate_t *cur_samplers[GS_MAX_TEXTURES];
	gs_vertbuffer_t *cur_vertex_buffer;
	gs_indexbuffer_t *cur_index_buffer;
	gs_shader_t *cur_vertex_shader;
	gs_shader_t *cur_pixel_shader;
	gs_swapchain_t *cur_swap;
	struct gs_program *cur_program;

	struct gs_program *first_program;

	enum gs_cull_mode cur_cull_mode;
	struct gs_rect cur_viewport;

	struct matrix4 cur_proj;
	struct matrix4 cur_view;
	struct matrix4 cur_viewproj;

	DARRAY(struct matrix4) proj_stack;

	struct fbo_info *cur_fbo;
};

extern struct fbo_info *get_fbo(gs_texture_t *tex, uint32_t width,
				uint32_t height);

extern void gl_update(gs_device_t *device);

extern struct gl_platform *gl_platform_create(gs_device_t *device,
					      uint32_t adapter);
extern void gl_platform_destroy(struct gl_platform *platform);

extern BOOL gl_platform_init_swapchain(struct gs_swap_chain *swap);
extern void gl_platform_cleanup_swapchain(struct gs_swap_chain *swap);

extern struct gl_windowinfo *
gl_windowinfo_create(const struct gs_init_data *info);
extern void gl_windowinfo_destroy(struct gl_windowinfo *wi);

extern void gl_getclientsize(const struct gs_swap_chain *swap, uint32_t *width,
			     uint32_t *height);
